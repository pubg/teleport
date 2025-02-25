/*

 Copyright 2022 Gravitational, Inc.

 Licensed under the Apache License, Version 2.0 (the "License");
 you may not use this file except in compliance with the License.
 You may obtain a copy of the License at

     http://www.apache.org/licenses/LICENSE-2.0

 Unless required by applicable law or agreed to in writing, software
 distributed under the License is distributed on an "AS IS" BASIS,
 WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 See the License for the specific language governing permissions and
 limitations under the License.

*/

package dbcmd

import (
	"fmt"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/gravitational/teleport/lib/client"
	"github.com/gravitational/teleport/lib/client/db"
	"github.com/gravitational/teleport/lib/client/db/mysql"
	"github.com/gravitational/teleport/lib/client/db/postgres"
	"github.com/gravitational/teleport/lib/defaults"
	"github.com/gravitational/teleport/lib/tlsca"
	"github.com/gravitational/teleport/lib/utils"

	"github.com/gravitational/trace"

	"github.com/sirupsen/logrus"
)

const (
	// postgresBin is the Postgres client binary name.
	postgresBin = "psql"
	// cockroachBin is the Cockroach client binary name.
	cockroachBin = "cockroach"
	// mysqlBin is the MySQL client binary name.
	mysqlBin = "mysql"
	// mariadbBin is the MariaDB client binary name.
	mariadbBin = "mariadb"
	// mongoshBin is the Mongo Shell client binary name.
	mongoshBin = "mongosh"
	// mongoBin is the Mongo client binary name.
	mongoBin = "mongo"
	// redisBin is the Redis client binary name.
	redisBin = "redis-cli"
	// mssqlBin is the SQL Server client program name.
	mssqlBin = "mssql-cli"
)

// execer is an abstraction of Go's exec module, as this one doesn't specify any interfaces.
// This interface exists only to enable mocking.
type execer interface {
	// RunCommand runs a system command.
	RunCommand(name string, arg ...string) ([]byte, error)
	// LookPath returns a full path to a binary if this one is found in system PATH,
	// error otherwise.
	LookPath(file string) (string, error)
	// Command returns the Cmd struct to execute the named program with the given arguments.
	Command(name string, arg ...string) *exec.Cmd
}

// systemExecer implements execer interface by using Go exec module.
type systemExecer struct{}

// RunCommand is a wrapper for exec.Command(...).Output()
func (s systemExecer) RunCommand(name string, arg ...string) ([]byte, error) {
	return exec.Command(name, arg...).Output()
}

// LookPath is a wrapper for exec.LookPath(...)
func (s systemExecer) LookPath(file string) (string, error) {
	return exec.LookPath(file)
}

// Command is a wrapper for exec.Command(...)
func (s systemExecer) Command(name string, arg ...string) *exec.Cmd {
	return exec.Command(name, arg...)
}

// CLICommandBuilder holds data needed to build a CLI command from args passed to NewCmdBuilder.
// Any calls to the exec package within CLICommandBuilder methods that need to be mocked should
// use the exe field rather than calling the package directly.
type CLICommandBuilder struct {
	tc          *client.TeleportClient
	rootCluster string
	profile     *client.ProfileStatus
	db          *tlsca.RouteToDatabase
	host        string
	port        int
	options     connectionCommandOpts
	uid         utils.UID

	exe execer
}

func NewCmdBuilder(tc *client.TeleportClient, profile *client.ProfileStatus,
	db *tlsca.RouteToDatabase, rootClusterName string, opts ...ConnectCommandFunc,
) *CLICommandBuilder {
	var options connectionCommandOpts
	for _, opt := range opts {
		opt(&options)
	}

	// In TLS routing mode a local proxy is started on demand so connect to it.
	host, port := tc.DatabaseProxyHostPort(*db)
	if options.localProxyPort != 0 && options.localProxyHost != "" {
		host = options.localProxyHost
		port = options.localProxyPort
	}

	if options.log == nil {
		options.log = logrus.NewEntry(logrus.StandardLogger())
	}

	return &CLICommandBuilder{
		tc:          tc,
		profile:     profile,
		db:          db,
		host:        host,
		port:        port,
		options:     options,
		rootCluster: rootClusterName,
		uid:         utils.NewRealUID(),

		exe: &systemExecer{},
	}
}

// GetConnectCommand returns a command that can connect the user directly to the given database
// using an appropriate CLI database client. It takes into account cluster configuration, binaries
// available on the system and in some cases it even connects to the database to check which exact
// version of the database the user is running.
//
// Underneath it uses exec.Command, so the resulting command will always be expanded to its absolute
// path if exec.LookPath was able to find the given binary on user's system.
//
// If CLICommandBuilder's options.tolerateMissingCLIClient is set to true, GetConnectCommand
// shouldn't return an error if it cannot locate a client binary. Check WithTolerateMissingCLIClient
// docs for more details.
func (c *CLICommandBuilder) GetConnectCommand() (*exec.Cmd, error) {
	switch c.db.Protocol {
	case defaults.ProtocolPostgres:
		return c.getPostgresCommand(), nil

	case defaults.ProtocolCockroachDB:
		return c.getCockroachCommand(), nil

	case defaults.ProtocolMySQL:
		return c.getMySQLCommand()

	case defaults.ProtocolMongoDB:
		return c.getMongoCommand(), nil

	case defaults.ProtocolRedis:
		return c.getRedisCommand(), nil

	case defaults.ProtocolSQLServer:
		return c.getSQLServerCommand(), nil
	}

	return nil, trace.BadParameter("unsupported database protocol: %v", c.db)
}

// GetConnectCommandNoAbsPath works just like GetConnectCommand, with the only difference being that
// it guarantees that the command will always be in its base form, never in an absolute path
// resolved to the binary location. This is useful for situations where the resulting command is
// meant to be copied and then pasted into an interactive shell, rather than being run directly
// by a tool like tsh.
func (c *CLICommandBuilder) GetConnectCommandNoAbsPath() (*exec.Cmd, error) {
	cmd, err := c.GetConnectCommand()

	if err != nil {
		return nil, trace.Wrap(err)
	}

	if filepath.IsAbs(cmd.Path) {
		cmd.Path = filepath.Base(cmd.Path)
	}

	return cmd, nil
}

func (c *CLICommandBuilder) getPostgresCommand() *exec.Cmd {
	return c.exe.Command(postgresBin, c.getPostgresConnString())
}

func (c *CLICommandBuilder) getCockroachCommand() *exec.Cmd {
	// If cockroach CLI client is not available, fallback to psql.
	if _, err := c.exe.LookPath(cockroachBin); err != nil {
		c.options.log.Debugf("Couldn't find %q client in PATH, falling back to %q: %v.",
			cockroachBin, postgresBin, err)
		return c.getPostgresCommand()
	}
	return c.exe.Command(cockroachBin, "sql", "--url", c.getPostgresConnString())
}

// getPostgresConnString returns the connection string for postgres.
func (c *CLICommandBuilder) getPostgresConnString() string {
	return postgres.GetConnString(
		db.New(c.tc, *c.db, *c.profile, c.rootCluster, c.host, c.port),
		c.options.noTLS,
		c.options.printFormat,
	)
}

// getMySQLCommonCmdOpts returns common command line arguments for mysql and mariadb.
// Currently, the common options are: user, database, host, port and protocol.
func (c *CLICommandBuilder) getMySQLCommonCmdOpts() []string {
	args := make([]string, 0)
	if c.db.Username != "" {
		args = append(args, "--user", c.db.Username)
	}
	if c.db.Database != "" {
		args = append(args, "--database", c.db.Database)
	}

	if c.options.localProxyPort != 0 {
		args = append(args, "--port", strconv.Itoa(c.options.localProxyPort))
		args = append(args, "--host", c.options.localProxyHost)
		// MySQL CLI treats localhost as a special value and tries to use Unix Domain Socket for connection
		// To enforce TCP connection protocol needs to be explicitly specified.
		if c.options.localProxyHost == "localhost" {
			args = append(args, "--protocol", "TCP")
		}
	}

	return args
}

// getMariaDBArgs returns arguments unique for mysql cmd shipped by MariaDB and mariadb cmd. Common options for mysql
// between Oracle and MariaDB version are covered by getMySQLCommonCmdOpts().
func (c *CLICommandBuilder) getMariaDBArgs() []string {
	args := c.getMySQLCommonCmdOpts()

	if c.options.noTLS {
		return args
	}

	sslCertPath := c.profile.DatabaseCertPathForCluster(c.tc.SiteName, c.db.ServiceName)

	args = append(args, []string{"--ssl-key", c.profile.KeyPath()}...)
	args = append(args, []string{"--ssl-ca", c.profile.CACertPathForCluster(c.rootCluster)}...)
	args = append(args, []string{"--ssl-cert", sslCertPath}...)

	// Flag below verifies "Common Name" check on the certificate provided by the server.
	// This option is disabled by default.
	if !c.tc.InsecureSkipVerify {
		args = append(args, "--ssl-verify-server-cert")
	}

	return args
}

// getMySQLOracleCommand returns arguments unique for mysql cmd shipped by Oracle. Common options between
// Oracle and MariaDB version are covered by getMySQLCommonCmdOpts().
func (c *CLICommandBuilder) getMySQLOracleCommand() *exec.Cmd {
	args := c.getMySQLCommonCmdOpts()

	if c.options.noTLS {
		return c.exe.Command(mysqlBin, args...)
	}

	// defaults-group-suffix must be first.
	groupSuffix := []string{fmt.Sprintf("--defaults-group-suffix=_%v-%v", c.tc.SiteName, c.db.ServiceName)}
	args = append(groupSuffix, args...)

	// override the ssl-mode from a config file is --insecure flag is provided to 'tsh db connect'.
	if c.tc.InsecureSkipVerify {
		args = append(args, fmt.Sprintf("--ssl-mode=%s", mysql.MySQLSSLModeVerifyCA))
	}

	return c.exe.Command(mysqlBin, args...)
}

// getMySQLCommand returns mariadb command if the binary is on the path. Otherwise,
// mysql command is returned. Both mysql versions (MariaDB and Oracle) are supported.
func (c *CLICommandBuilder) getMySQLCommand() (*exec.Cmd, error) {
	// Check if mariadb client is available. Prefer it over mysql client even if connecting to MySQL server.
	if c.isMariaDBBinAvailable() {
		args := c.getMariaDBArgs()
		return c.exe.Command(mariadbBin, args...), nil
	}

	// Check for mysql binary. In case the caller doesn't tolerate a missing CLI client, return with
	// error as mysql and mariadb are missing. There is nothing else we can do here.
	if !c.isMySQLBinAvailable() {
		if c.options.tolerateMissingCLIClient {
			return c.getMySQLOracleCommand(), nil
		}

		return nil, trace.NotFound("neither %q nor %q CLI clients were found, please make sure an appropriate CLI client is available in $PATH", mysqlBin, mariadbBin)
	}

	// Check which flavor is installed. Otherwise, we don't know which ssl flag to use.
	// At the moment of writing mysql binary shipped by Oracle and MariaDB accept different ssl parameters and have the same name.
	mySQLMariaDBFlavor, err := c.isMySQLBinMariaDBFlavor()
	if mySQLMariaDBFlavor && err == nil {
		args := c.getMariaDBArgs()
		return c.exe.Command(mysqlBin, args...), nil
	}

	// Either we failed to check the flavor or binary comes from Oracle. Regardless return mysql/Oracle command.
	return c.getMySQLOracleCommand(), nil
}

// isMariaDBBinAvailable returns true if "mariadb" binary is found in the system PATH.
func (c *CLICommandBuilder) isMariaDBBinAvailable() bool {
	_, err := c.exe.LookPath(mariadbBin)
	return err == nil
}

// isMySQLBinAvailable returns true if "mysql" binary is found in the system PATH.
func (c *CLICommandBuilder) isMySQLBinAvailable() bool {
	_, err := c.exe.LookPath(mysqlBin)
	return err == nil
}

// isMongoshBinAvailable returns true if "mongosh" binary is found in the system PATH.
func (c *CLICommandBuilder) isMongoshBinAvailable() bool {
	_, err := c.exe.LookPath(mongoshBin)
	return err == nil
}

// isMySQLBinMariaDBFlavor checks if mysql binary comes from Oracle or MariaDB.
// true is returned when binary comes from MariaDB, false when from Oracle.
func (c *CLICommandBuilder) isMySQLBinMariaDBFlavor() (bool, error) {
	// Check if mysql comes from Oracle or MariaDB
	mysqlVer, err := c.exe.RunCommand(mysqlBin, "--version")
	if err != nil {
		// Looks like incorrect mysql installation.
		return false, trace.Wrap(err)
	}

	// Check which flavor is installed. Otherwise, we don't know which ssl flag to use.
	// Example output:
	// Oracle:
	// mysql  Ver 8.0.27-0ubuntu0.20.04.1 for Linux on x86_64 ((Ubuntu))
	// MariaDB:
	// mysql  Ver 15.1 Distrib 10.3.32-MariaDB, for debian-linux-gnu (x86_64) using readline 5.2
	return strings.Contains(strings.ToLower(string(mysqlVer)), "mariadb"), nil
}

func (c *CLICommandBuilder) getMongoCommand() *exec.Cmd {
	// look for `mongosh`
	hasMongosh := c.isMongoshBinAvailable()

	args := []string{
		"--host", c.host,
		"--port", strconv.Itoa(c.port),
	}

	if !c.options.noTLS {
		// Starting with Mongo 4.2 there is an updated set of flags.
		// We are using them with `mongosh` as otherwise warnings will get displayed.
		type tlsFlags struct {
			tls            string
			tlsCertKeyFile string
			tlsCAFile      string
		}

		var flags tlsFlags

		if hasMongosh {
			flags = tlsFlags{tls: "--tls", tlsCertKeyFile: "--tlsCertificateKeyFile", tlsCAFile: "--tlsCAFile"}
		} else {
			flags = tlsFlags{tls: "--ssl", tlsCertKeyFile: "--sslPEMKeyFile", tlsCAFile: "--sslCAFile"}
		}

		args = append(args,
			flags.tls,
			flags.tlsCertKeyFile,
			c.profile.DatabaseCertPathForCluster(c.tc.SiteName, c.db.ServiceName))

		if c.options.caPath != "" {
			// caPath is set only if mongo connects to the Teleport Proxy via ALPN SNI Local Proxy
			// and connection is terminated by proxy identity certificate.
			args = append(args, []string{flags.tlsCAFile, c.options.caPath}...)
		} else {
			// mongosh does not load system CAs by default which will cause issues if
			// the proxy presents a certificate signed by a non-recognized authority
			// which your system trusts (e.g. mkcert).
			if hasMongosh {
				args = append(args, "--tlsUseSystemCA")
			}
		}
	}

	if c.db.Database != "" {
		args = append(args, c.db.Database)
	}

	// use `mongosh` if available
	if hasMongosh {
		return c.exe.Command(mongoshBin, args...)
	}

	// fall back to `mongo` if `mongosh` isn't found
	return c.exe.Command(mongoBin, args...)
}

// getRedisCommand returns redis-cli commands used by 'tsh db connect' when connecting to a Redis instance.
func (c *CLICommandBuilder) getRedisCommand() *exec.Cmd {
	// TODO(jakub): Add "-3" when Teleport adds support for Redis RESP3 protocol.
	args := []string{
		"-h", c.host,
		"-p", strconv.Itoa(c.port),
	}

	if !c.options.noTLS {
		args = append(args,
			"--tls",
			"--key", c.profile.KeyPath(),
			"--cert", c.profile.DatabaseCertPathForCluster(c.tc.SiteName, c.db.ServiceName))

		if c.tc.InsecureSkipVerify {
			args = append(args, "--insecure")
		}

		if c.options.caPath != "" {
			args = append(args, []string{"--cacert", c.options.caPath}...)
		}
	}

	// append database number if provided
	if c.db.Database != "" {
		args = append(args, []string{"-n", c.db.Database}...)
	}

	return c.exe.Command(redisBin, args...)
}

func (c *CLICommandBuilder) getSQLServerCommand() *exec.Cmd {
	args := []string{
		// Host and port must be comma-separated.
		"-S", fmt.Sprintf("%v,%v", c.host, c.port),
		"-U", c.db.Username,
		// Password is required by the client but doesn't matter as we're
		// connecting to local proxy.
		"-P", c.uid.New(),
	}

	if c.db.Database != "" {
		args = append(args, "-d", c.db.Database)
	}

	return c.exe.Command(mssqlBin, args...)
}

type connectionCommandOpts struct {
	localProxyPort           int
	localProxyHost           string
	caPath                   string
	noTLS                    bool
	printFormat              bool
	tolerateMissingCLIClient bool
	log                      *logrus.Entry
}

// ConnectCommandFunc is a type for functions returned by the "With*" functions in this package.
// A function of type ConnectCommandFunc changes connectionCommandOpts of CLICommandBuilder based on
// the arguments passed to a "With*" function.
type ConnectCommandFunc func(*connectionCommandOpts)

// WithLocalProxy makes CLICommandBuilder pass appropriate args to the CLI database clients that
// will let them connect to a database through a local proxy.
// In most cases it means using the passed host and port as the address, but some database clients
// require additional flags in those scenarios.
func WithLocalProxy(host string, port int, caPath string) ConnectCommandFunc {
	return func(opts *connectionCommandOpts) {
		opts.localProxyPort = port
		opts.localProxyHost = host
		opts.caPath = caPath
	}
}

// WithNoTLS is the connect command option that makes the command connect
// without TLS.
//
// It is used when connecting through the local proxy that was started in
// mutual TLS mode (i.e. with a client certificate).
func WithNoTLS() ConnectCommandFunc {
	return func(opts *connectionCommandOpts) {
		opts.noTLS = true
	}
}

// WithPrintFormat is the connect command option that hints the command will be
// printed instead of being executed.
func WithPrintFormat() ConnectCommandFunc {
	return func(opts *connectionCommandOpts) {
		opts.printFormat = true
	}
}

// WithLogger is the connect command option that allows the caller to pass a logger that will be
// used by CLICommandBuilder.
func WithLogger(log *logrus.Entry) ConnectCommandFunc {
	return func(opts *connectionCommandOpts) {
		opts.log = log
	}
}

// WithTolerateMissingCLIClient is the connect command option that makes CLICommandBuilder not
// return an error in case a specific binary couldn't be found in the system. Instead it should
// return the command with just a base version of the binary name, without an absolute path.
//
// In general CLICommandBuilder doesn't return an error in that scenario as it uses exec.Command
// underneath. However, there are some specific situations where we need to execute some of the
// binaries before returning the final command.
//
// The flag is mostly for scenarios where the caller doesn't care that the final command might not
// work.
func WithTolerateMissingCLIClient() ConnectCommandFunc {
	return func(opts *connectionCommandOpts) {
		opts.tolerateMissingCLIClient = true
	}
}
