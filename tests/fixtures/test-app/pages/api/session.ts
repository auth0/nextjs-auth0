export default function sessionHandler(req, res): void {
  const json = JSON.stringify((global as any).getSession(req, res));
  res.status(200).json(json);
}
