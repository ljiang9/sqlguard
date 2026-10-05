"""Enables `python -m sqlguard`."""
if __package__:
    from .sqlguard import main
else:  # 直接运行 `python __main__.py` 的兜底
    from sqlguard import main

if __name__ == "__main__":
    raise SystemExit(main())
