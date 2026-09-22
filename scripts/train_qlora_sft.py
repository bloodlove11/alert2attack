#!/usr/bin/env python3
"""Smoke QLoRA SFT of Qwen2.5-7B-Instruct (strategy spec §5). Lightning GPU only.

Does not change metrics.py. Does not distill test. Requires --allow-smoke when
filtered N < 12.

Train deps are the locked optional group (not the API/CI default):

    uv sync --group train

See docs/TRAIN.md. Do not pip-install unpinned unsloth/trl on Lightning.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

QLORA_CONFIG = {
    "base": "unsloth/Qwen2.5-7B-Instruct",
    "quant": "4bit-nf4",
    "rank": 8,
    "lora_alpha": 16,
    "lora_dropout": 0.0,
    "target_modules": [
        "q_proj",
        "k_proj",
        "v_proj",
        "o_proj",
        "gate_proj",
        "up_proj",
        "down_proj",
    ],
    "learning_rate": 2e-4,
    "lr_scheduler_type": "cosine",
    "warmup_ratio": 0.03,
    "num_train_epochs": 1,
    "per_device_train_batch_size": 1,
    "gradient_accumulation_steps": 8,
    "max_seq_length": 4096,
    "optim": "adamw_8bit",
}


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            obj = json.loads(line)
            if isinstance(obj, dict):
                rows.append(obj)
    return rows


def _format_chat(tokenizer: Any, messages: list[dict[str, Any]]) -> str:
    return tokenizer.apply_chat_template(
        messages,
        tokenize=False,
        add_generation_prompt=False,
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sft-jsonl", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--allow-smoke", action="store_true")
    parser.add_argument("--max-seq-length", type=int, default=QLORA_CONFIG["max_seq_length"])
    args = parser.parse_args(argv)

    rows = _read_jsonl(args.sft_jsonl)
    train_rows = [r for r in rows if r.get("subset") == "train"]
    eval_rows = [r for r in rows if r.get("subset") == "eval"]
    n_cases = len({str(r.get("scenario_id")) for r in rows})
    if n_cases < 8:
        print(f"kill: n_cases={n_cases} < 8", file=sys.stderr)
        return 2
    if n_cases < 12 and not args.allow_smoke:
        print(f"kill: n_cases={n_cases} < 12; pass --allow-smoke for EXP-004 smoke", file=sys.stderr)
        return 2
    if not train_rows:
        print("kill: no train threads", file=sys.stderr)
        return 2

    try:
        import unsloth  # noqa: F401, I001 — must import before trl/transformers
        from datasets import Dataset
        from trl import SFTConfig, SFTTrainer
        from unsloth import FastLanguageModel
    except ImportError as exc:
        print(
            "train_qlora_sft.py needs unsloth, datasets, and trl on a CUDA machine "
            f"(Lightning T4). Install with: uv sync --group train. Import failed: {exc}",
            file=sys.stderr,
        )
        return 3

    max_seq = int(args.max_seq_length)
    model, tokenizer = FastLanguageModel.from_pretrained(
        model_name=str(QLORA_CONFIG["base"]),
        max_seq_length=max_seq,
        load_in_4bit=True,
    )
    model = FastLanguageModel.get_peft_model(
        model,
        r=int(QLORA_CONFIG["rank"]),
        target_modules=list(QLORA_CONFIG["target_modules"]),
        lora_alpha=int(QLORA_CONFIG["lora_alpha"]),
        lora_dropout=float(QLORA_CONFIG["lora_dropout"]),
        bias="none",
        use_gradient_checkpointing="unsloth",
    )

    def _texts(subset: list[dict[str, Any]]) -> list[dict[str, str]]:
        out: list[dict[str, str]] = []
        for row in subset:
            messages = row.get("messages")
            if not isinstance(messages, list):
                continue
            try:
                text = _format_chat(tokenizer, messages)
            except Exception:
                continue
            if text.strip():
                out.append({"text": text})
        return out

    train_ds = Dataset.from_list(_texts(train_rows))
    eval_ds = Dataset.from_list(_texts(eval_rows)) if eval_rows else None
    if len(train_ds) == 0:
        print("kill: tokenizer produced zero train strings", file=sys.stderr)
        return 2

    args.out.mkdir(parents=True, exist_ok=True)
    steps_per_epoch = max(1, len(train_ds) // int(QLORA_CONFIG["gradient_accumulation_steps"]))
    warmup_steps = max(1, int(float(QLORA_CONFIG["warmup_ratio"]) * steps_per_epoch))
    trainer = SFTTrainer(
        model=model,
        processing_class=tokenizer,
        train_dataset=train_ds,
        eval_dataset=eval_ds,
        args=SFTConfig(
            output_dir=str(args.out / "checkpoints"),
            per_device_train_batch_size=int(QLORA_CONFIG["per_device_train_batch_size"]),
            gradient_accumulation_steps=int(QLORA_CONFIG["gradient_accumulation_steps"]),
            warmup_steps=warmup_steps,
            num_train_epochs=int(QLORA_CONFIG["num_train_epochs"]),
            learning_rate=float(QLORA_CONFIG["learning_rate"]),
            lr_scheduler_type=str(QLORA_CONFIG["lr_scheduler_type"]),
            optim=str(QLORA_CONFIG["optim"]),
            fp16=True,
            bf16=False,
            logging_steps=1,
            save_strategy="no",
            eval_strategy="no",
            max_length=max_seq,
            dataset_text_field="text",
            packing=False,
            report_to=[],
            seed=41,
        ),
    )
    result = trainer.train()
    adapter_dir = args.out / "adapter"
    model.save_pretrained(str(adapter_dir))
    tokenizer.save_pretrained(str(adapter_dir))
    metrics = {
        "config": QLORA_CONFIG,
        "n_cases": n_cases,
        "n_train_threads": len(train_ds),
        "n_eval_threads": len(eval_ds) if eval_ds is not None else 0,
        "smoke": n_cases < 12,
        "train": {k: (float(v) if hasattr(v, "real") else v) for k, v in dict(result.metrics).items()},
        "adapter": str(adapter_dir),
    }
    metrics_path = args.out / "train_metrics.json"

    def _write_metrics() -> None:
        metrics_path.write_text(json.dumps(metrics, indent=2, default=str) + "\n", encoding="utf-8")

    _write_metrics()
    gguf_dir = args.out / "gguf"
    try:
        model.save_pretrained_gguf(str(gguf_dir), tokenizer, quantization_method="q4_k_m")
        metrics["gguf"] = str(gguf_dir)
        _write_metrics()
    except Exception as exc:  # noqa: BLE001 — GGUF is best-effort for Ollama
        print(f"gguf export skipped: {exc}", file=sys.stderr)
    print(json.dumps({"adapter": str(adapter_dir), "train_loss": metrics["train"].get("train_loss")}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
