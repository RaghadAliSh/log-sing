router.get('/get-admin-data', async (req, res) => {
    const token = req.header('x-auth-token');
    if (!token) {
        return res.status(401).json({ msg: 'No token, authorization denied' });
    }

    try {
        const decoded = jwt.verify(token, jwtSecret);
        req.user = decoded.user;

        const user = await User.findById(req.user.id).select('-password');
        if (!user) {
            return res.status(404).json({ msg: 'User not found' });
        }

        if (!user.isAdmin) {
            return res.status(403).json({ msg: 'Access denied. Admins only.' });
        }

        res.json({ email: user.email, isAdmin: user.isAdmin });
    } catch (error) {
        console.error(error.message);
        res.status(500).send('Server error');
    }
});
