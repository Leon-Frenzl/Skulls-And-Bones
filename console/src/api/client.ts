import { formatHttpError, formatNetworkError, type ConsoleNotice } from "../ui/errors.ts";

export interface ApiResult<T> {
  ok: boolean;
  status: number;
  data?: T;
  notice?: Omit<ConsoleNotice, "id" | "scope">;
}

export async function apiRequest<T>(
  path: string,
  actionLabel: string,
  init: RequestInit = {}
): Promise<ApiResult<T>> {
  try {
    const res = await fetch(path, init);
    if (!res.ok) {
      const body = await res.text().catch(() => "");
      return {
        ok: false,
        status: res.status,
        notice: formatHttpError(actionLabel, res.status, body),
      };
    }
    const text = await res.text().catch(() => "");
    const data = text ? (JSON.parse(text) as T) : (undefined as T);
    return { ok: true, status: res.status, data };
  } catch (err) {
    return {
      ok: false,
      status: 0,
      notice: formatNetworkError(actionLabel, err),
    };
  }
}
