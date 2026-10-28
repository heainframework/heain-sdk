package heain

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
)

// Sealed data (core C10 S2, POST /v1/app/sealed/...): records sealed under a
// key core keeps and never hands to the app -- unlike DataKey, the app cannot
// open them itself. They open only under an approved P5 grant (a Proposal of
// a type seal.policies lists, whose data names "scope" and "readers"), and
// every opening is audited by core. Use it for data that must exist but must
// not be readable without a decision: individual votes, health results.

// SealInput is one record to seal.
type SealInput struct {
	ID   string `json:"id"`
	Data []byte `json:"data_b64"`
}

// SealedRecord is a sealed record: store it as is, with its id.
type SealedRecord struct {
	ID     string `json:"id"`
	Sealed []byte `json:"sealed_b64"`
}

// OpenedRecord is a record opened under a grant.
type OpenedRecord struct {
	ID   string `json:"id"`
	Data []byte `json:"data_b64"`
}

// SealOpening is one opening under a grant, as core's ledger keeps it.
type SealOpening struct {
	At        string   `json:"at"`
	Reader    string   `json:"reader"`
	App       string   `json:"app"`
	Name      string   `json:"name"`
	RecordIDs []string `json:"record_ids"`
}

// Seal seals records under core's seal key name for scope (and lane, when
// the manifest declares unlinkable lanes). Up to 1000 records per call.
func (a *App) Seal(ctx context.Context, name, scope, lane string, recs []SealInput) ([]SealedRecord, string, error) {
	if len(recs) == 0 {
		return nil, "", fmt.Errorf("heain-sdk: nothing to seal")
	}
	var out struct {
		KeyID   string         `json:"key_id"`
		Records []SealedRecord `json:"records"`
	}
	body := map[string]any{"scope": scope, "lane": lane, "records": recs}
	if _, err := a.Core.Do(ctx, http.MethodPost, "/v1/app/sealed/"+url.PathEscape(name)+"/seal", nil, body, &out); err != nil {
		return nil, "", err
	}
	return out.Records, out.KeyID, nil
}

// OpenSealed opens records under grant (an approved P5 action id) for
// reader, an identity the grant names. Core refuses (403 seal_open_refused)
// when the grant is not approved, expired, of another type or app, does not
// name the reader or cover the records' scope, the reader is recused, or the
// grant's record limit would be exceeded. It returns the records and how
// many distinct records the grant has opened so far.
func (a *App) OpenSealed(ctx context.Context, name, grant, reader string, recs []SealedRecord) ([]OpenedRecord, int, error) {
	var out struct {
		Records []OpenedRecord `json:"records"`
		N       int            `json:"opened_under_grant"`
	}
	body := map[string]any{"grant": grant, "reader": reader, "records": recs}
	if _, err := a.Core.Do(ctx, http.MethodPost, "/v1/app/sealed/"+url.PathEscape(name)+"/open", nil, body, &out); err != nil {
		return nil, 0, err
	}
	return out.Records, out.N, nil
}

// SealOpenings lists the openings of this app's sealed data name under grant.
func (a *App) SealOpenings(ctx context.Context, name, grant string) ([]SealOpening, error) {
	var out struct {
		Openings []SealOpening `json:"openings"`
	}
	_, err := a.Core.Do(ctx, http.MethodGet, "/v1/app/sealed/"+url.PathEscape(name)+"/opens?grant="+url.QueryEscape(grant), nil, nil, &out)
	return out.Openings, err
}

// DestroySealKey crypto-shreds this node's seal key name for scope (and
// lane): its sealed records can never be opened again. Core refuses (409
// seal_held) while a legal hold names the data.
func (a *App) DestroySealKey(ctx context.Context, name, scope, lane string) error {
	q := url.Values{}
	if scope != "" {
		q.Set("scope", scope)
	}
	if lane != "" {
		q.Set("lane", lane)
	}
	_, err := a.Core.Do(ctx, http.MethodDelete, "/v1/app/sealed/"+url.PathEscape(name)+"?"+q.Encode(), nil, nil, nil)
	return err
}
