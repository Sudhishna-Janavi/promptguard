"""demo.py — end-to-end PromptGuard demo (no typing required).

Scans a sample prompt containing real-format secrets and prints the verdict,
the findings (masked), and the redacted-safe version. Useful for the demo
video: the output only ever shows redacted/masked text, never a raw secret.

Run:  python demo.py
"""

import scanner

SAMPLE = (
    "Hey Kiro, help me debug my deploy config.\n"
    "AWS key: AKIAIOSFODNN7EXAMPLE\n"
    "OpenAI key: sk-Ab12Cd34Ef56Gh78Ij90Kl12Mn34Op56\n"
    "GitHub token: ghp_1234567890abcdefABCDEF1234567890abcd\n"
    "DB password = SuperSecret123\n"
    "Email me at jane.doe@company.com\n"
    "Card on file: 4111 1111 1111 1111\n"
)


def main():
    result = scanner.scan(SAMPLE)
    print("=" * 62)
    print("  PromptGuard — local privacy firewall for LLMs")
    print("=" * 62)
    print("\nOriginal prompt (what you were about to send to an AI):\n")
    print(SAMPLE)
    print(f"VERDICT: {result.verdict}\n")
    print("Findings:")
    for f in result.findings:
        print(f"  [{f.severity:<6}] {f.type:<22} preview: {f.masked_preview}")
    print("\nSafe version to send instead:")
    print("-" * 62)
    print(result.redacted_text)
    print("-" * 62)


if __name__ == "__main__":
    main()
