package integration

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
	"sigs.k8s.io/kind/pkg/cluster"
	"sigs.k8s.io/kind/pkg/log"
)

type clusterFixture struct {
	name       string
	configPath string
	provider   *cluster.Provider
	log        log.Logger
}

type tLogger struct {
	*testing.T
	level log.Level
}

func (t tLogger) Warn(msg string) {
	if t.Enabled() {
		t.Log(msg)
	}
}

func (t tLogger) Warnf(format string, args ...interface{}) {
	if t.Enabled() {
		t.Logf(format, args...)
	}
}

func (t tLogger) Error(msg string) {
	if t.Enabled() {
		t.Log(msg)
	}
}

func (t tLogger) Errorf(format string, args ...interface{}) {
	if t.Enabled() {
		t.Logf(format, args...)
	}
}

func (t tLogger) Info(msg string) {
	if t.Enabled() {
		t.Log(msg)
	}
}

func (t tLogger) Infof(format string, args ...interface{}) {
	if t.Enabled() {
		t.Logf(format, args...)
	}
}

func (t tLogger) V(l log.Level) log.InfoLogger {
	return tLogger{t.T, l}
}

func (t tLogger) Enabled() bool {
	return t.level == 0
}

func createTestCluster(t *testing.T) *clusterFixture {

	now := time.Now()

	log := tLogger{t, 0}

	fixture := &clusterFixture{
		name:       fmt.Sprintf("%s-%d", strings.ToLower(t.Name()), now.UnixMilli()),
		configPath: filepath.Join(t.TempDir(), "kubecfg"),
		provider:   cluster.NewProvider(cluster.ProviderWithLogger(log)),
		log:        log,
	}

	t.Log("Creating test cluster with KinD...")
	err := fixture.provider.Create(
		fixture.name,
		cluster.CreateWithRetain(false),
		cluster.CreateWithWaitForReady(time.Duration(30*time.Second)),
		cluster.CreateWithKubeconfigPath(fixture.configPath),
		cluster.CreateWithDisplayUsage(false),
	)
	require.NoError(t, err)

	t.Log("Test cluster created")

	clientConfig, err := clientcmd.BuildConfigFromFlags("", fixture.configPath)
	require.NoError(t, err)

	clientset, err := kubernetes.NewForConfig(clientConfig)
	require.NoError(t, err)

	t.Log("Populating cluster...")
	require.NoError(t, populateCluster(clientset))

	t.Cleanup(func() {
		t.Log("Destroying test cluster")
		err := fixture.provider.Delete(fixture.name, fixture.configPath)
		require.NoError(t, err)
	})

	return fixture
}

func populateCluster(clientset *kubernetes.Clientset) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	noOptions := metav1.CreateOptions{}

	ns := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: "teletest",
		},
	}

	_, err := clientset.CoreV1().Namespaces().Create(ctx, ns, noOptions)
	if err != nil {
		return err
	}

	ciTeleport := rbacv1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{
			Name: "ci-teleport",
		},
		Rules: []rbacv1.PolicyRule{
			{
				APIGroups: []string{""},
				Resources: []string{"users", "groups"},
				Verbs:     []string{"impersonate"},
			}, {
				APIGroups: []string{""},
				Resources: []string{"namespaces"},
				Verbs:     []string{"create"},
			},
		},
	}

	// clusterrole granting overarching privileges
	_, err = clientset.RbacV1().ClusterRoles().Create(ctx, &ciTeleport, noOptions)
	if err != nil {
		return err
	}

	// role to allow pod operations in teletest namespace
	ciTeleportSA := rbacv1.Role{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "ci-teleport-sa",
			Namespace: ns.Name,
		},
		Rules: []rbacv1.PolicyRule{{
			APIGroups: []string{""},
			Resources: []string{"pods"},
			Verbs:     []string{"create"},
		}},
	}
	_, err = clientset.RbacV1().Roles(ns.Name).Create(ctx, &ciTeleportSA, noOptions)
	if err != nil {
		return err
	}

	// role to allow pod operations via impersonation in teletest namespace
	ciTeleportGroup := rbacv1.Role{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "ci-teleport-group",
			Namespace: ns.Name,
		},
		Rules: []rbacv1.PolicyRule{
			{
				APIGroups:     []string{""},
				Resources:     []string{"pods"},
				Verbs:         []string{"get"},
				ResourceNames: []string{"test-pod"},
			}, {
				APIGroups:     []string{""},
				Resources:     []string{"pods/exec"},
				Verbs:         []string{"create"},
				ResourceNames: []string{"test-pod"},
			}, {
				APIGroups:     []string{""},
				Resources:     []string{"pods/portforward"},
				Verbs:         []string{"create"},
				ResourceNames: []string{"test-pod"},
			},
		},
	}
	_, err = clientset.RbacV1().Roles(ns.Name).Create(ctx, &ciTeleportGroup, noOptions)
	if err != nil {
		return err
	}

	ciTeleportBinding := rbacv1.ClusterRoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name: "ci-teleport",
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "ClusterRole",
			Name:     ciTeleport.Name,
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      rbacv1.ServiceAccountKind,
				Name:      "teleport-sa",
				Namespace: ns.Name,
			},
		},
	}
	_, err = clientset.RbacV1().ClusterRoleBindings().Create(ctx, &ciTeleportBinding, noOptions)
	if err != nil {
		return err
	}

	ciTeleportSABinding := rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "ci-teleport-sa",
			Namespace: ns.Name,
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "Role",
			Name:     ciTeleportSA.Name,
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      rbacv1.ServiceAccountKind,
				Name:      "teleport-sa",
				Namespace: ns.Name,
			},
		},
	}
	_, err = clientset.RbacV1().RoleBindings(ns.Name).Create(ctx, &ciTeleportSABinding, noOptions)
	if err != nil {
		return err
	}

	ciTeleportGroupBinding := rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "ci-teleport-group",
			Namespace: ns.Name,
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "Role",
			Name:     ciTeleportGroup.Name,
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      rbacv1.GroupKind,
				Name:      "teleport-ci-test-group",
				Namespace: ns.Name,
			},
		},
	}
	_, err = clientset.RbacV1().RoleBindings(ns.Name).Create(ctx, &ciTeleportGroupBinding, noOptions)
	if err != nil {
		return err
	}

	return nil
}

// echo "Creating the Kubernetes Service Account with minimal RBAC permissions."
// kubectl apply -f - <<EOF
// apiVersion: v1
// kind: Namespace
// metadata:
//   name: ${NAMESPACE}
// ---
// apiVersion: v1
// kind: ServiceAccount
// metadata:
//   name: ${TELEPORT_SA}
//   namespace: ${NAMESPACE}
// ---
// apiVersion: rbac.authorization.k8s.io/v1
// kind: ClusterRole
// metadata:
//   name: teleport-role
// rules:
// - apiGroups:
//   - ""
//   resources:
//   - users
//   - groups
//   - serviceaccounts
//   verbs:
//   - impersonate
// - apiGroups:
//   - ""
//   resources:
//   - pods
//   verbs:
//   - get
// - apiGroups:
//   - "authorization.k8s.io"
//   resources:
//   - selfsubjectaccessreviews
//   - selfsubjectrulesreviews
//   verbs:
//   - create
// ---
// apiVersion: rbac.authorization.k8s.io/v1
// kind: ClusterRoleBinding
// metadata:
//   name: teleport-crb
// roleRef:
//   apiGroup: rbac.authorization.k8s.io
//   kind: ClusterRole
//   name: teleport-role
// subjects:
// - kind: ServiceAccount
//   name: ${TELEPORT_SA}
//   namespace: ${NAMESPACE}
// EOF
