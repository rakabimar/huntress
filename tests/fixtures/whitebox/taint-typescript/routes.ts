export function unsafe(req: any) {
  const url = req.query.url;
  return fetch(url);
}

export function safe(req: any) {
  const url = req.query.url;
  const checked = validateExternalUrl(url);
  return fetch(checked);
}
