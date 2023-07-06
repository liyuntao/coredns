package cmbdfw

import (
	"context"
	"github.com/coredns/coredns/plugin"
	"github.com/coredns/coredns/plugin/pkg/nonwriter"
	"github.com/coredns/coredns/plugin/pkg/replacer"
	"github.com/coredns/coredns/request"
	"github.com/gobwas/glob"
	"github.com/miekg/dns"
	"strings"
)

type CmbiDnsFw struct {
	AllowPtnList []glob.Glob
	EnableMock   bool
	Next         plugin.Handler
}

// ServeDNS implements the plugin.Handler interface.
func (p CmbiDnsFw) ServeDNS(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {
	// plugin cmbdfw only handles A or AAAA record
	if r.Question[0].Qtype != dns.TypeA && r.Question[0].Qtype != dns.TypeAAAA || "localhost." == r.Question[0].Name || strings.Contains(r.Question[0].Name, "cmbi.") {
		return plugin.NextOrFailure(p.Name(), p.Next, ctx, w, r)
	}

	var (
		//status    = -1
		respMsg *dns.Msg
		//errfw     error
	)

	state := request.Request{W: w, Req: r}

	isDomainAllow := EvaluateReRules(ctx, state, p.AllowPtnList)

	log.Infof("queryName=%s | afterEvaluate isDomainAllow=%t", state.Req.Question[0].Name, isDomainAllow)

	if isDomainAllow || p.EnableMock {
		if p.EnableMock {
			log.Warningf("[mock]refused req for domain=%s", state.Req.Question[0].Name)
		}

		writer := nonwriter.New(w)
		reader := NewReader(writer)

		// ask other plugins to resolve
		_, err := plugin.NextOrFailure(p.Name(), p.Next, ctx, reader, r)
		if err != nil {
			m := new(dns.Msg)
			m = m.SetRcode(r, dns.RcodeServerFailure)
			w.WriteMsg(m)
			return dns.RcodeSuccess, err
		}
		respMsg = writer.Msg
		w.WriteMsg(respMsg)
		return dns.RcodeSuccess, nil
	}
	log.Warningf("refused req for domain=%s", state.Req.Question[0].Name)
	return dns.RcodeRefused, nil
}

// Name implements the Handler interface.
func (p CmbiDnsFw) Name() string { return "cmbdfw" }

func EvaluateReRules(tx context.Context, state request.Request, allowRulesRe []glob.Glob) bool {
	if len(allowRulesRe) == 0 {
		return true
	}

	domain := state.Req.Question[0].Name
	if last := len(domain) - 1; last >= 0 && domain[last] == '.' {
		domain = domain[:last]
	}

	for _, ptn := range allowRulesRe {
		if ptn.Match(domain) {
			return true
		}
	}
	return false
}

const (
	// CommonLogFormat is the common log format.
	CommonLogFormat = `{remote}:{port} ` + replacer.EmptyValue + ` {>id} "{type} {class} {name} {proto} {size} {>do} {>bufsize}" {rcode} {>rflags} {rsize} {duration}`
	// CombinedLogFormat is the combined log format.
	CombinedLogFormat = CommonLogFormat + ` "{>opcode}"`
	// DefaultLogFormat is the default log format.
	DefaultLogFormat = CommonLogFormat
)
