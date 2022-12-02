export default async function helloWorld(req, res) {
  res.status(200).json({ text: 'Hello World!' });
}
