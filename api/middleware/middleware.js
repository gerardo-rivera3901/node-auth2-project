const isValid = (req, res, next) => {
  const user = req.body;
  if (!user || !user.username || !user.password) {
    res.status(401).json({ message: 'Enter a valid username and password'});
  } else {
    next();
  }
};

module.exports = {
  isValid
};