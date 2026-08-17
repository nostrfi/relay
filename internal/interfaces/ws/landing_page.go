package ws

import (
	_ "embed"
	"html/template"
	"log/slog"
	"net/http"
)

//go:embed landing.html
var landingPageHTML string

var landingPageTpl = template.Must(template.New("landing").Parse(landingPageHTML))

func (h *RelayHandler) serveLandingPage(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := landingPageTpl.Execute(w, h.relayInfo); err != nil {
		slog.Error("landing page template error", "error", err)
	}
}
