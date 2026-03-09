let jwt = require('jsonwebtoken')
let userController = require('../controllers/users')
module.exports = {
    checkLogin: async function (req, res, next) {
        let token
        if (req.cookies.token) {
            token = req.cookies.token
        } else {
            token = req.headers.authorization;
            if (!token || !token.startsWith("Bearer")) {
                res.status(403).send({ message: "ban chua dang nhap" })
                return;
            }
            token = token.split(' ')[1];
        }
        try {
            let result = jwt.verify(token, 'secret');
            if (result && result.id) {
                req.userId = result.id;
                next();
            } else {
                res.status(403).send({ message: "ban chua dang nhap" })
            }
        } catch (err) {
            res.status(403).send({ message: "token khong hop le" })
        }
    },
    checkRole: function (...requiredRole) {
        return async function (req, res, next) {
            try {
                let userId = req.userId;
                let user = await userController.FindUserById(userId);
                
                if (!user) {
                    return res.status(403).send({ message: "user not found" });
                }
                
                if (!user.role || !user.role.name) {
                    return res.status(403).send({ message: "role not found" });
                }
                
                let currentRole = user.role.name;
                if (requiredRole.includes(currentRole)) {
                    next();
                } else {
                    res.status(403).send({ message: "ban khong co quyen" });
                }
            } catch (err) {
                res.status(500).send({ message: "error checking role: " + err.message });
            }
        }
    }
}
