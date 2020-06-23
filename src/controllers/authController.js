const router = require('express').Router();
const User = require('../models/User');

const jwt = require('jsonwebtoken');

const config = require('../config');

const verifyToken = require('./verifyToken');

router.post('/signup', async (req, res, next) => {
	const { username, email, password } = req.body;
	const user = new User({
		username,
		email,
		password
	})

	const token = jwt.sign({id: user._id}, config.secret, {
		expiresIn: 60 * 60 * 24
	});

	user.password = await user.encryptPassword(user.password);
	await user.save();

	res.json({auth: true, token });
});

router.get('/me', verifyToken, async (req, res, next) => {
	const user = await User.findById(req.userId, { password: 0 });

	if(!user) return res.status(404).json({ message: 'User not found' });

	res.json(user)
});

router.post('/signin', async (req, res, next) => {
	const { email, password } = req.body;
	const user = await User.findOne({ email });

	if(!user) return res.status(404).json({ message: 'The email doesn`t exists! '});

	const validPassword = await user.validatePassword(password);
	if(!validPassword) return res.status(401).json({auth: false, token: null});

	const token = jwt.sign({id: user._id}, config.secret, {
		expiresIn: 60 * 60 * 24
	});

	res.json({ auth: true, token });
});
module.exports = router;