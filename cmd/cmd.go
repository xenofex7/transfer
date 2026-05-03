package cmd

import (
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/dutchcoders/transfer.sh/server"
	"github.com/dutchcoders/transfer.sh/server/storage"
	"github.com/fatih/color"
	"github.com/urfave/cli/v2"
)

// Version is inject at build time
var Version = "0.0.0"
var helpTemplate = `NAME:
{{.Name}} - {{.Usage}}

DESCRIPTION:
{{.Description}}

USAGE:
{{.Name}} {{if .Flags}}[flags] {{end}}command{{if .Flags}}{{end}} [arguments...]

COMMANDS:
{{range .Commands}}{{join .Names ", "}}{{ "\t" }}{{.Usage}}
{{end}}{{if .Flags}}
FLAGS:
{{range .Flags}}{{.}}
{{end}}{{end}}
VERSION:
` + Version +
	`{{ "\n"}}`

var globalFlags = []cli.Flag{
	&cli.StringFlag{
		Name:    "listener",
		Usage:   "127.0.0.1:8080",
		Value:   "127.0.0.1:8080",
		EnvVars: []string{"LISTENER"},
	},
	&cli.StringFlag{
		Name:    "temp-path",
		Usage:   "path to temp files",
		Value:   os.TempDir(),
		EnvVars: []string{"TEMP_PATH"},
	},
	&cli.StringFlag{
		Name:    "web-path",
		Usage:   "path to static web files",
		Value:   "",
		EnvVars: []string{"WEB_PATH"},
	},
	&cli.StringFlag{
		Name:    "proxy-path",
		Usage:   "path prefix when service is run behind a proxy",
		Value:   "",
		EnvVars: []string{"PROXY_PATH"},
	},
	&cli.StringFlag{
		Name:    "proxy-port",
		Usage:   "port of the proxy when the service is run behind a proxy",
		Value:   "",
		EnvVars: []string{"PROXY_PORT"},
	},
	&cli.StringFlag{
		Name:    "email-contact",
		Usage:   "email address to link in Contact Us (front end)",
		Value:   "",
		EnvVars: []string{"EMAIL_CONTACT"},
	},
	&cli.IntFlag{
		Name:    "rate-limit",
		Usage:   "requests per minute",
		Value:   0,
		EnvVars: []string{"RATE_LIMIT"},
	},
	&cli.IntFlag{
		Name:    "purge-days",
		Usage:   "number of days after uploads are purged automatically",
		Value:   360,
		EnvVars: []string{"PURGE_DAYS"},
	},
	&cli.IntFlag{
		Name:    "purge-interval",
		Usage:   "interval in hours to run the automatic purge for",
		Value:   24,
		EnvVars: []string{"PURGE_INTERVAL"},
	},
	&cli.Int64Flag{
		Name:    "max-upload-size",
		Usage:   "max limit for upload, in kilobytes",
		Value:   0,
		EnvVars: []string{"MAX_UPLOAD_SIZE"},
	},
	&cli.StringFlag{
		Name:    "log",
		Usage:   "/var/log/transfersh.log",
		Value:   "",
		EnvVars: []string{"LOG"},
	},
	&cli.StringFlag{
		Name:    "basedir",
		Usage:   "path to storage",
		Value:   "",
		EnvVars: []string{"BASEDIR"},
	},
	&cli.StringFlag{
		Name:    "clamav-host",
		Usage:   "clamav-host",
		Value:   "",
		EnvVars: []string{"CLAMAV_HOST"},
	},
	&cli.BoolFlag{
		Name:    "perform-clamav-prescan",
		Usage:   "perform-clamav-prescan",
		EnvVars: []string{"PERFORM_CLAMAV_PRESCAN"},
	},
	&cli.IntFlag{
		Name:    "clamav-scan-timeout",
		Usage:   "clamav scan timeout in seconds",
		Value:   60,
		EnvVars: []string{"CLAMAV_SCAN_TIMEOUT"},
	},
	&cli.StringFlag{
		Name:    "http-auth-user",
		Usage:   "user for http basic auth",
		Value:   "",
		EnvVars: []string{"HTTP_AUTH_USER"},
	},
	&cli.StringFlag{
		Name:    "http-auth-pass",
		Usage:   "pass for http basic auth",
		Value:   "",
		EnvVars: []string{"HTTP_AUTH_PASS"},
	},
	&cli.StringFlag{
		Name:    "http-auth-htpasswd",
		Usage:   "htpasswd file http basic auth",
		Value:   "",
		EnvVars: []string{"HTTP_AUTH_HTPASSWD"},
	},
	&cli.StringFlag{
		Name:    "http-auth-ip-whitelist",
		Usage:   "comma separated list of ips allowed to upload without being challenged an http auth",
		Value:   "",
		EnvVars: []string{"HTTP_AUTH_IP_WHITELIST"},
	},
	&cli.StringFlag{
		Name:    "ip-whitelist",
		Usage:   "comma separated list of ips allowed to connect to the service",
		Value:   "",
		EnvVars: []string{"IP_WHITELIST"},
	},
	&cli.StringFlag{
		Name:    "ip-blacklist",
		Usage:   "comma separated list of ips not allowed to connect to the service",
		Value:   "",
		EnvVars: []string{"IP_BLACKLIST"},
	},
	&cli.StringFlag{
		Name:    "cors-domains",
		Usage:   "comma separated list of domains allowed for CORS requests",
		Value:   "",
		EnvVars: []string{"CORS_DOMAINS"},
	},
	&cli.IntFlag{
		Name:    "random-token-length",
		Usage:   "",
		Value:   10,
		EnvVars: []string{"RANDOM_TOKEN_LENGTH"},
	},
	&cli.StringFlag{
		Name:    "upload-webhook-url",
		Usage:   "URL that receives a JSON POST for upload, download and delete events",
		Value:   "",
		EnvVars: []string{"UPLOAD_WEBHOOK_URL"},
	},
	&cli.StringFlag{
		Name:    "webhook-token",
		Usage:   "optional bearer token sent as Authorization header on every webhook POST",
		Value:   "",
		EnvVars: []string{"WEBHOOK_TOKEN"},
	},
}

// Cmd wraps cli.app
type Cmd struct {
	*cli.App
}

func versionCommand(_ *cli.Context) error {
	fmt.Println(color.YellowString("transfer.sh %s: Easy file sharing from the command line", Version))
	return nil
}

// New is the factory for transfer.sh
func New() *Cmd {
	logger := log.New(os.Stdout, "[transfer.sh]", log.LstdFlags)

	app := cli.NewApp()
	app.Name = "transfer.sh"
	app.Authors = []*cli.Author{}
	app.Usage = "transfer.sh"
	app.Description = `Easy file sharing from the command line`
	app.Version = Version
	app.Flags = globalFlags
	app.CustomAppHelpTemplate = helpTemplate
	app.Commands = []*cli.Command{
		{
			Name:   "version",
			Action: versionCommand,
		},
	}

	app.Before = func(c *cli.Context) error {
		return nil
	}

	app.Action = func(c *cli.Context) error {
		var options []server.OptionFn
		if v := c.String("listener"); v != "" {
			options = append(options, server.Listener(v))
		}

		if v := c.String("cors-domains"); v != "" {
			options = append(options, server.CorsDomains(v))
		}

		if v := c.String("web-path"); v != "" {
			options = append(options, server.WebPath(v))
		}

		if v := c.String("proxy-path"); v != "" {
			options = append(options, server.ProxyPath(v))
		}

		if v := c.String("proxy-port"); v != "" {
			options = append(options, server.ProxyPort(v))
		}

		if v := c.String("email-contact"); v != "" {
			options = append(options, server.EmailContact(v))
		}

		if v := c.String("temp-path"); v != "" {
			options = append(options, server.TempPath(v))
		}

		if v := c.String("log"); v != "" {
			options = append(options, server.LogFile(logger, v))
		} else {
			options = append(options, server.Logger(logger))
		}

		if v := c.String("clamav-host"); v != "" {
			options = append(options, server.ClamavHost(v))
		}

		if v := c.Bool("perform-clamav-prescan"); v {
			if c.String("clamav-host") == "" {
				return errors.New("clamav-host not set")
			}

			options = append(options, server.PerformClamavPrescan(v))
		}

		if v := c.Int("clamav-scan-timeout"); v > 0 {
			options = append(options, server.ClamavScanTimeout(v))
		}

		if v := c.Int64("max-upload-size"); v > 0 {
			options = append(options, server.MaxUploadSize(v))
		}

		if v := c.Int("rate-limit"); v > 0 {
			options = append(options, server.RateLimit(v))
		}

		v := c.Int("random-token-length")
		options = append(options, server.RandomTokenLength(v))

		if v := c.String("upload-webhook-url"); v != "" {
			options = append(options, server.UploadWebhookURL(v))
		}
		if v := c.String("webhook-token"); v != "" {
			options = append(options, server.WebhookToken(v))
		}

		purgeDays := c.Int("purge-days")
		purgeInterval := c.Int("purge-interval")
		if purgeDays > 0 && purgeInterval > 0 {
			options = append(options, server.Purge(purgeDays, purgeInterval))
		}

		if httpAuthUser := c.String("http-auth-user"); httpAuthUser == "" {
		} else if httpAuthPass := c.String("http-auth-pass"); httpAuthPass == "" {
		} else {
			options = append(options, server.HTTPAuthCredentials(httpAuthUser, httpAuthPass))
		}

		if httpAuthHtpasswd := c.String("http-auth-htpasswd"); httpAuthHtpasswd != "" {
			options = append(options, server.HTTPAuthHtpasswd(httpAuthHtpasswd))
		}

		if httpAuthIPWhitelist := c.String("http-auth-ip-whitelist"); httpAuthIPWhitelist != "" {
			ipFilterOptions := server.IPFilterOptions{}
			ipFilterOptions.AllowedIPs = strings.Split(httpAuthIPWhitelist, ",")
			ipFilterOptions.BlockByDefault = true
			options = append(options, server.HTTPAUTHFilterOptions(ipFilterOptions))
		}

		applyIPFilter := false
		ipFilterOptions := server.IPFilterOptions{}
		if ipWhitelist := c.String("ip-whitelist"); ipWhitelist != "" {
			applyIPFilter = true
			ipFilterOptions.AllowedIPs = strings.Split(ipWhitelist, ",")
			ipFilterOptions.BlockByDefault = true
		}

		if ipBlacklist := c.String("ip-blacklist"); ipBlacklist != "" {
			applyIPFilter = true
			ipFilterOptions.BlockedIPs = strings.Split(ipBlacklist, ",")
		}

		if applyIPFilter {
			options = append(options, server.FilterOptions(ipFilterOptions))
		}

		basedir := c.String("basedir")
		if basedir == "" {
			return errors.New("basedir not set")
		}
		store, err := storage.NewLocalStorage(basedir, logger)
		if err != nil {
			return err
		}
		options = append(options, server.UseStorage(store))
		options = append(options, server.UseDeletionLog(filepath.Join(basedir, ".deletions.jsonl")))

		srvr, err := server.New(
			options...,
		)

		if err != nil {
			logger.Println(color.RedString("Error starting server: %s", err.Error()))
			return err
		}

		srvr.Run()
		return nil
	}

	return &Cmd{
		App: app,
	}
}
