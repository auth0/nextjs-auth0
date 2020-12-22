export default (global as any).withApiAuthRequired(function protectedApiRoute(req, res) {
  res.status(200).json({ foo: 'bar' });
});
