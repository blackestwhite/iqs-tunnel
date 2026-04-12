package dnsmsg

import "testing"

func TestTXTQueryAndResponse(t *testing.T) {
	query, err := BuildTXTQuery(17, "abc.example.com")
	if err != nil {
		t.Fatalf("build query: %v", err)
	}
	question, err := ParseQuestion(query)
	if err != nil {
		t.Fatalf("parse question: %v", err)
	}
	if question.Name != "abc.example.com" {
		t.Fatalf("unexpected qname: %s", question.Name)
	}
	response, err := BuildTXTResponse(question, "hello")
	if err != nil {
		t.Fatalf("build response: %v", err)
	}
	id, txts, err := ParseTXTResponse(response)
	if err != nil {
		t.Fatalf("parse response: %v", err)
	}
	if id != 17 || len(txts) != 1 || txts[0] != "hello" {
		t.Fatalf("unexpected response: id=%d txt=%v", id, txts)
	}
}
