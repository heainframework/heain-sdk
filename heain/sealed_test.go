package heain

import (
	"bytes"
	"context"
	"strings"
	"testing"
)

// heain-core C10 S2: the sealed-data calls send and read what core expects
func TestSealedCalls(t *testing.T) {
	e := startEnv(t)
	ctx := context.Background()
	recs, kid, err := e.svc.Seal(ctx, "ballots", "d12", "", []SealInput{{ID: "b1", Data: []byte("cand-7")}})
	if err != nil || len(recs) != 1 || recs[0].ID != "b1" || !strings.HasSuffix(kid, "/ballots/d12") {
		t.Fatalf("seal: %v %v %v", recs, kid, err)
	}
	if _, _, err := e.svc.Seal(ctx, "ballots", "d12", "", nil); err == nil {
		t.Fatal("nothing to seal")
	}
	if _, _, err := e.svc.OpenSealed(ctx, "ballots", "g-waiting", "inv-1", recs); err == nil || !strings.Contains(err.Error(), "seal_open_refused") {
		t.Fatalf("refusal: %v", err)
	}
	got, n, err := e.svc.OpenSealed(ctx, "ballots", "g-ok", "inv-1", recs)
	if err != nil || n != 1 || !bytes.Equal(got[0].Data, []byte("cand-7")) {
		t.Fatalf("open: %v %d %v", got, n, err)
	}
	if err := e.svc.DestroySealKey(ctx, "ballots", "d12", ""); err != nil {
		t.Fatal(err)
	}
}
