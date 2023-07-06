package cmbdfw

import (
	"github.com/coredns/caddy"
	"github.com/coredns/coredns/core/dnsserver"
	"github.com/coredns/coredns/plugin"
	clog "github.com/coredns/coredns/plugin/pkg/log"
	"github.com/gobwas/glob"
	"strconv"
)

var log = clog.NewWithPlugin("cmbdfw")

func init() { plugin.Register("cmbdfw", setup) }

func setup(c *caddy.Controller) error {
	reRules, isEnableMock, err := parseConfig(c)
	if err != nil {
		return plugin.Error("log", err)
	}
	log.Info("plugin cmbdfw loaded, totalRule=" + strconv.Itoa(len(reRules)) + " enableMock=" + strconv.FormatBool(isEnableMock))

	dnsserver.GetConfig(c).AddPlugin(func(next plugin.Handler) plugin.Handler {
		return CmbiDnsFw{
			AllowPtnList: reRules,
			EnableMock:   isEnableMock,
			Next:         next,
		}
	})

	return nil
}

func parseConfig(c *caddy.Controller) ([]glob.Glob, bool, error) {
	for c.Next() {
		isMockEnable := false
		maybeMockCfg := c.RemainingArgs()
		if len(maybeMockCfg) == 1 && maybeMockCfg[0] == "mockOn" {
			log.Infof("plugin mock mode: on")
			isMockEnable = true
		}

		var allowRules []glob.Glob

		for c.NextBlock() {
			globMatcher, err := glob.Compile(c.Val())
			if err != nil {
				log.Errorf("error compiling pattern {%s}. Will skip", c.Val())
				continue
			}
			allowRules = append(allowRules, globMatcher)
		}

		if len(allowRules) > 0 {
			return allowRules, isMockEnable, nil
		}
	}
	return nil, false, c.ArgErr()
}
