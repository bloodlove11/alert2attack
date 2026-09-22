import json
from pathlib import Path

from alert2attack.agent.llm import (
    ChatMessage,
    ChatResponse,
    ScriptedChat,
    ToolCallRequest,
    scripted_responses_from_json,
)


def test_scripted_chat_pops_responses() -> None:
    chat = ScriptedChat(
        [
            ChatResponse(content="plan"),
            ChatResponse(
                tool_calls=(ToolCallRequest(id="1", name="get_alert", arguments={}),),
            ),
        ]
    )
    r1 = chat.complete([ChatMessage(role="user", content="hi")])
    assert r1.content == "plan"
    r2 = chat.complete([ChatMessage(role="user", content="next")])
    assert r2.tool_calls[0].name == "get_alert"
    assert len(chat.calls) == 2


def test_scripted_responses_from_json_loads_content_and_tool_calls(tmp_path: Path) -> None:
    path = tmp_path / "responses.json"
    path.write_text(
        json.dumps(
            [
                {"content": "plan"},
                {
                    "content": None,
                    "tool_calls": [
                        {"name": "get_alert", "arguments": {}},
                        {"id": "explicit", "name": "get_process_tree", "arguments": {"pid": 4120}},
                    ],
                },
            ]
        ),
        encoding="utf-8",
    )
    responses = scripted_responses_from_json(path)
    assert len(responses) == 2
    assert responses[0].content == "plan"
    assert responses[0].tool_calls == ()
    assert responses[1].tool_calls[0] == ToolCallRequest(id="call_0", name="get_alert", arguments={})
    assert responses[1].tool_calls[1] == ToolCallRequest(
        id="explicit", name="get_process_tree", arguments={"pid": 4120}
    )


def test_scripted_responses_from_json_shared_list_feeds_two_chats(tmp_path: Path) -> None:
    path = tmp_path / "responses.json"
    path.write_text(json.dumps([{"content": "plan"}, {"content": "write"}]), encoding="utf-8")
    responses = scripted_responses_from_json(path)
    first = ScriptedChat(responses)
    second = ScriptedChat(responses)
    assert first.complete([ChatMessage(role="user", content="a")]).content == "plan"
    assert first.complete([ChatMessage(role="user", content="b")]).content == "write"
    assert [r.content for r in responses] == ["plan", "write"]
    assert second.complete([ChatMessage(role="user", content="c")]).content == "plan"
