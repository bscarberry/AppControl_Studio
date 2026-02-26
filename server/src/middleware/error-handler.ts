import { Request, Response, NextFunction } from "express";

export function errorHandler(
  err: Error,
  _req: Request,
  res: Response,
  _next: NextFunction
): void {
  console.error("[Error]", err.message, err.stack);
  res.status(500).json({
    ok: false,
    error: {
      code: "INTERNAL_ERROR",
      message: process.env.NODE_ENV === "production"
        ? "An internal server error occurred."
        : err.message,
    },
  });
}

export function requestSizeGuard(maxBytes: number) {
  return (req: Request, res: Response, next: NextFunction): void => {
    const contentLength = parseInt(req.headers["content-length"] ?? "0", 10);
    if (contentLength > maxBytes) {
      res.status(413).json({
        ok: false,
        error: {
          code: "PAYLOAD_TOO_LARGE",
          message: `Request body exceeds ${Math.round(maxBytes / 1024 / 1024)}MB limit.`,
        },
      });
      return;
    }
    next();
  };
}
