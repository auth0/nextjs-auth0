export default async function accessTokenHandler(req, res): Promise<void> {
  try {
    const json = JSON.stringify(await (global as any).getAccessToken(req, res));
    res.status(200).json(json);
  } catch (error) {
    res.statusMessage = error.message;
    res.status(error.status || 500).end(error.message);
  }
}
