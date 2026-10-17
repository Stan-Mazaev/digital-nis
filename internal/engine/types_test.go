package engine

import (
	"bytes"
	"strings"
	"testing"
)

func sampleToken() DigitalNISRubles {
	return DigitalNISRubles{
		TokenID:         strings.Repeat("a", 64),
		Amount:          485_000_000, // 4 850 000.00 ₽ в копейках
		TargetColorTag:  strings.Repeat("b", 64),
		MilitaryIDHash:  strings.Repeat("c", 64),
		BeneficiaryINN:  "7701982341",
		CadastralNumber: "77:01:0001001:102",
		IssuerSignature: bytes.Repeat([]byte{0xAB}, 64),
		IssuedAt:        1_700_000_000,
		MaxLockDuration: 30 * 24 * 3600,
	}
}

func sampleContract() *EscrowContract {
	return &EscrowContract{
		DealID:    "DEAL-2026-0001",
		Token:     sampleToken(),
		Trigger:   TriggerRegistration,
		Status:    StatusLocked,
		CreatedAt: 1_700_000_000,
		UpdatedAt: 1_700_000_000,
		TimeoutAt: 1_700_000_000 + 30*24*3600,
	}
}

func TestEscrowStatus_IsValid(t *testing.T) {
	for _, s := range []EscrowStatus{
		StatusCreated, StatusLocked, StatusReleased, StatusRefunded,
	} {
		if !s.IsValid() {
			t.Fatalf("%q should be valid", s)
		}
	}
	if EscrowStatus("BOGUS").IsValid() {
		t.Fatal("bogus status accepted")
	}
	if EscrowStatus("").IsValid() {
		t.Fatal("empty status accepted")
	}
}

func TestDigitalNISRubles_Validate_OK(t *testing.T) {
	tok := sampleToken()
	if err := tok.Validate(); err != nil {
		t.Fatalf("valid token rejected: %v", err)
	}
}

func TestDigitalNISRubles_Validate_MissingFields(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*DigitalNISRubles)
	}{
		{"no TokenID", func(x *DigitalNISRubles) { x.TokenID = "" }},
		{"no Amount", func(x *DigitalNISRubles) { x.Amount = 0 }},
		{"no ColorTag", func(x *DigitalNISRubles) { x.TargetColorTag = "" }},
		{"no INN", func(x *DigitalNISRubles) { x.BeneficiaryINN = "" }},
		{"no Kadastr", func(x *DigitalNISRubles) { x.CadastralNumber = "" }},
		{"no Signature", func(x *DigitalNISRubles) { x.IssuerSignature = nil }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			tok := sampleToken()
			c.mutate(&tok)
			if err := tok.Validate(); err == nil {
				t.Fatal("expected error")
			}
		})
	}
}

func TestEscrowContract_Validate_OK(t *testing.T) {
	c := sampleContract()
	if err := c.Validate(); err != nil {
		t.Fatalf("valid contract rejected: %v", err)
	}
}

func TestEscrowContract_Validate_TimeoutBeforeCreated(t *testing.T) {
	c := sampleContract()
	c.TimeoutAt = c.CreatedAt - 1
	if err := c.Validate(); err == nil {
		t.Fatal("expected error for TimeoutAt <= CreatedAt")
	}
}

func TestEscrowContract_Serialize_Roundtrip(t *testing.T) {
	orig := sampleContract()
	data, err := orig.Serialize()
	if err != nil {
		t.Fatalf("Serialize: %v", err)
	}
	restored, err := DeserializeEscrow(data)
	if err != nil {
		t.Fatalf("DeserializeEscrow: %v", err)
	}
	if restored.DealID != orig.DealID {
		t.Fatalf("DealID mismatch: got %q, want %q", restored.DealID, orig.DealID)
	}
	if restored.Token.Amount != orig.Token.Amount {
		t.Fatalf("Amount mismatch")
	}
	if !bytes.Equal(restored.Token.IssuerSignature, orig.Token.IssuerSignature) {
		t.Fatal("IssuerSignature mismatch after roundtrip")
	}
	if restored.Status != orig.Status {
		t.Fatalf("Status mismatch")
	}
}

func TestDeserializeEscrow_Empty(t *testing.T) {
	if _, err := DeserializeEscrow(nil); err == nil {
		t.Fatal("expected error for nil input")
	}
	if _, err := DeserializeEscrow([]byte{}); err == nil {
		t.Fatal("expected error for empty input")
	}
}

func TestDeserializeEscrow_MalformedJSON(t *testing.T) {
	if _, err := DeserializeEscrow([]byte("{not json}")); err == nil {
		t.Fatal("expected error for malformed JSON")
	}
}

func TestEscrowContract_Clone_NoAliasing(t *testing.T) {
	orig := sampleContract()
	orig.RosreestrProof = []byte{1, 2, 3, 4}

	cp := orig.Clone()

	// Меняем байты клона — оригинал не должен измениться.
	cp.RosreestrProof[0] = 0xFF
	cp.Token.IssuerSignature[0] = 0xFF

	if orig.RosreestrProof[0] == 0xFF {
		t.Fatal("clone aliases RosreestrProof")
	}
	if orig.Token.IssuerSignature[0] == 0xFF {
		t.Fatal("clone aliases IssuerSignature")
	}
}

func TestSerialize_NilContract(t *testing.T) {
	var c *EscrowContract
	if _, err := c.Serialize(); err == nil {
		t.Fatal("expected error for nil contract")
	}
}
