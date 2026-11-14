package ledger

import (
	"context"
	"testing"
	"time"
)

// TestChatHistoryRoundTrip: the conversation survives, in order, with its cards.
func TestChatHistoryRoundTrip(t *testing.T) {
	store, ctx := mandateTestStore(t)
	eng, err := store.CreateEngagement(ctx, "chat-"+time.Now().Format("150405.000000"),
		map[string]any{"include": []string{"127.0.0.1"}})
	if err != nil {
		t.Fatalf("create engagement: %v", err)
	}
	t.Cleanup(func() { _, _ = store.Pool().Exec(context.Background(), `DELETE FROM engagements WHERE id=$1`, eng.ID) })

	if _, err := store.AppendChat(ctx, eng.ID, "user", "先看看有没有 git 暴露", nil); err != nil {
		t.Fatalf("append user: %v", err)
	}
	cards := []map[string]any{{"type": "note", "text": "我来看看"}}
	if _, err := store.AppendChat(ctx, eng.ID, "assistant", "好的,先跑只读检查", cards); err != nil {
		t.Fatalf("append assistant: %v", err)
	}
	if _, err := store.AppendChat(ctx, eng.ID, "system", "nope", nil); err == nil {
		t.Fatal("an unknown role was accepted")
	}

	msgs, err := store.ChatHistory(ctx, eng.ID, 50)
	if err != nil {
		t.Fatalf("history: %v", err)
	}
	if len(msgs) != 2 {
		t.Fatalf("history = %d messages, want 2", len(msgs))
	}
	if msgs[0].Role != "user" || msgs[1].Role != "assistant" {
		t.Fatalf("order = %s,%s", msgs[0].Role, msgs[1].Role)
	}
	if string(msgs[1].Cards) == "[]" || string(msgs[1].Cards) == "" {
		t.Fatalf("cards did not survive: %s", msgs[1].Cards)
	}
}

// TestChatMessagesAreAppendOnly: history is a record, not a scratch pad.
func TestChatMessagesAreAppendOnly(t *testing.T) {
	store, ctx := mandateTestStore(t)
	eng, err := store.CreateEngagement(ctx, "chat-ao-"+time.Now().Format("150405.000000"),
		map[string]any{"include": []string{"127.0.0.1"}})
	if err != nil {
		t.Fatalf("create engagement: %v", err)
	}
	t.Cleanup(func() { _, _ = store.Pool().Exec(context.Background(), `DELETE FROM engagements WHERE id=$1`, eng.ID) })

	m, err := store.AppendChat(ctx, eng.ID, "user", "原文", nil)
	if err != nil {
		t.Fatalf("append: %v", err)
	}
	if _, err := store.Pool().Exec(ctx, `UPDATE chat_messages SET content='改写' WHERE id=$1`, m.ID); err == nil {
		t.Fatal("chat_messages allowed an UPDATE")
	}
	if _, err := store.Pool().Exec(ctx, `DELETE FROM chat_messages WHERE id=$1`, m.ID); err == nil {
		t.Fatal("chat_messages allowed a DELETE")
	}
}
