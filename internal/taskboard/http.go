package taskboard

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
)

// Auth authenticates a signed action challenge from a registered agent —
// satisfied by *aghub.Store. Actions are namespaced "task.*" so signatures
// cannot be replayed against relay endpoints.
type Auth interface {
	VerifyAgentChallenge(action, aid string, ts, keyStateSeq uint64, sigB64 string) error
}

// Server exposes the board over HTTP. Reads are open (D44: guests read);
// every mutation requires a KEL-signed challenge.
type Server struct {
	store *Store
	auth  Auth
}

func NewServer(store *Store, auth Auth) *Server { return &Server{store: store, auth: auth} }

type authFields struct {
	AID         string `json:"aid"`
	TS          uint64 `json:"ts"`
	KeyStateSeq uint64 `json:"key_state_seq"`
	Sig         string `json:"sig"`
}

type mutateReq struct {
	authFields
	CardID     string `json:"card_id,omitempty"`
	Title      string `json:"title,omitempty"`
	TaskDocCID string `json:"taskdoc_cid,omitempty"`
	Column     string `json:"column,omitempty"`
	Note       string `json:"note,omitempty"`
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /tasks/board", s.hBoard)
	mux.HandleFunc("GET /tasks/cards/{id}", s.hCard)
	for action, fn := range map[string]func(mutateReq) (*Card, error){
		"task.create":  func(r mutateReq) (*Card, error) { return s.store.Create(r.AID, r.Title, r.TaskDocCID, r.Column) },
		"task.move":    func(r mutateReq) (*Card, error) { return s.store.Move(r.AID, r.CardID, r.Column) },
		"task.claim":   func(r mutateReq) (*Card, error) { return s.store.Claim(r.AID, r.CardID) },
		"task.submit":  func(r mutateReq) (*Card, error) { return s.store.Submit(r.AID, r.CardID, r.Note) },
		"task.accept":  func(r mutateReq) (*Card, error) { return s.store.Accept(r.AID, r.CardID) },
		"task.reject":  func(r mutateReq) (*Card, error) { return s.store.Reject(r.AID, r.CardID, r.Note) },
		"task.block":   func(r mutateReq) (*Card, error) { return s.store.Block(r.AID, r.CardID, r.Note) },
		"task.unblock": func(r mutateReq) (*Card, error) { return s.store.Unblock(r.AID, r.CardID) },
	} {
		path := "POST /tasks/" + strings.TrimPrefix(action, "task.")
		mux.HandleFunc(path, s.mutation(action, fn))
	}
	return withCORS(mux)
}

func (s *Server) mutation(action string, fn func(mutateReq) (*Card, error)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req mutateReq
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad request"})
			return
		}
		if err := s.auth.VerifyAgentChallenge(action, req.AID, req.TS, req.KeyStateSeq, req.Sig); err != nil {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": err.Error()})
			return
		}
		card, err := fn(req)
		if err != nil {
			writeJSON(w, statusFor(err), map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"card": card})
	}
}

func (s *Server) hBoard(w http.ResponseWriter, _ *http.Request) {
	byCol, err := s.store.Board()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	type colView struct {
		Key   string `json:"key"`
		Name  string `json:"name"`
		Cards []Card `json:"cards"`
	}
	out := make([]colView, 0, len(Columns))
	for _, c := range Columns {
		cards := byCol[c.Key]
		if cards == nil {
			cards = []Card{}
		}
		out = append(out, colView{Key: c.Key, Name: c.Name, Cards: cards})
	}
	writeJSON(w, http.StatusOK, map[string]any{"columns": out})
}

func (s *Server) hCard(w http.ResponseWriter, r *http.Request) {
	card, events, err := s.store.Get(r.PathValue("id"))
	if err != nil {
		writeJSON(w, statusFor(err), map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"card": card, "events": events})
}

func statusFor(err error) int {
	switch {
	case errors.Is(err, ErrNotFound):
		return http.StatusNotFound
	case errors.Is(err, ErrForbidden):
		return http.StatusForbidden
	case errors.Is(err, ErrConflict):
		return http.StatusConflict
	case errors.Is(err, ErrValidation):
		return http.StatusBadRequest
	}
	return http.StatusInternalServerError
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

// withCORS mirrors the hub's permissive CORS (the paired web front end at
// hub.agentnetwork.org.cn is a browser origin reading the board).
func withCORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}
