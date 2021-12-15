const express = require('express')
const path = require('path')
const bodyParser = require('body-parser')
const mongoose = require('mongoose')
const User = require('./model/user')
const bcrypt = require('bcryptjs')

mongoose.connect('mongodb://localhost:27017/login-app-db', {
    useNewUrlParser: true,
    useUnifiedTopology: true
})

const app = express()
app.use('/', express.static(path.join(__dirname, 'static')))
app.use(bodyParser.json())

app.post('/api/register', async(req, res) => {
    console.log(req.body)
    // Analysts
    // Scripts reading databases

    const { username, password: plainTextPassword } = req.body

    const password = await bcrypt.hash(plainTextPassword, 10)

    try {
        const response = await User.creat({
            username,
            password
        })
        console.log('User created successfully: ', response)
    } catch (error) {
        console.log(error)
        return res.json({ status: 'error' })
    }

    // console.log(await bcrypt.hash(password, 10))
    // bcrypt, md5, sha1, sha256, sha512...

    // 1. The collision should be improbable
    // 2. The algorithm should be slow...

    // SPECIAL_FUNCTION(Password) -> CONVERTS PASSWORD TO GARBAGE

    // Hashing the passwords

    res.json({ status: 'ok' })
})

app.listen(9999, () => {
    console.log('Server up at 9999')
})