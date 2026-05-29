package scanner

import "testing"

func TestGraphQLFieldSuggestionLeak(t *testing.T) {
	if !graphqlFieldSuggestionLeak(`{"errors":[{"message":"Cannot query field x. Did you mean \"user\"?"}]}`) {
		t.Fatal("expected suggestion leak to be detected")
	}
	if graphqlFieldSuggestionLeak(`{"errors":[{"message":"Cannot query field x."}]}`) {
		t.Fatal("plain error must not be flagged")
	}
}

func TestGraphQLAliasAmplification(t *testing.T) {
	if !graphqlAliasAmplification(`{"data":{"a0":"Query","a1":"Query","a2":"Query","a3":"Query","a4":"Query"}}`) {
		t.Fatal("all aliases resolved must be detected")
	}
	if graphqlAliasAmplification(`{"data":{"a0":"Query"}}`) {
		t.Fatal("partial aliases must not be flagged")
	}
}

func TestGraphQLBatchAccepted(t *testing.T) {
	if !graphqlBatchAccepted(`[{"data":{"__typename":"Query"}},{"data":{"__typename":"Query"}},{"data":{"__typename":"Query"}}]`) {
		t.Fatal("multi-element batch must be detected")
	}
	if graphqlBatchAccepted(`{"data":{"__typename":"Query"}}`) {
		t.Fatal("non-array response must not be flagged")
	}
	if graphqlBatchAccepted(`[{"errors":[{"message":"batching disabled"}]}]`) {
		t.Fatal("single error array must not be flagged")
	}
}
