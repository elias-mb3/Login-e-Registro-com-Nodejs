//IMPORTS   
require('dotenv').config()
const express = require('express')
const mongoose = require('mongoose')
const bcrypt = require('bcrypt')
const jwt = require('jsonwebtoken')


const app = express()

// Config JSON express
app.use(express.json())

//Models
const User = require('./models/User')

//Private Route
app.get('/user/:id',checkToken, async (req,res) => {
    const id = req.params.id

    //usuario existe
    const user = await User.findById(id, '-password')

    if (!user) {
        return res.status(404).json({msg: 'Usuário não encontrado'})
    }    

    res.status(200).json({user})
})

//Verificando token
function checkToken (req, res, next) {
    //pegando token
    const authHeader = req.headers['authorization']
    
    const token = authHeader && authHeader.split(' ')[1]
    
    if (!token) {
        return res.status(401).json({msg: 'acesso negado'})
    }

    //validando se o token ta certo
    try{
        const secret = process.env.SECRET

        jwt.verify(token, secret)
        next()
    } catch (err) {
        res.status(400).json({msg: 'Token inválido!'})
    }
}


// Open Route
app.get('/', (req,res) => {
    res.status(200).json({msg: 'Olá Mundo'})
})

// Registrar Usuário
app.post('/auth/register', async(req,res) => {
    const {name, email, password, confirmpassword} =req.body

    // validações dos dados
    if (!name) {
        return res.status(422).json({msg: 'O nome é obrigatório!'})
    }
    if (!email) {
        return res.status(422).json({msg: 'O email é obrigatório!'})
    }
    if (!password) {
        return res.status(422).json({msg: 'A senha é obrigatória!'})
    }
    if (password !== confirmpassword) {
        return res.status(422).json({msg: 'As senhas precisam ser iguais!'})
    }

    //Confirmar se usuário existe
    const userExist = await User.findOne({ email: email })

    if(userExist) {
        return res.status(422).json({msg: 'Esse email já existe!'})
    }

    //Criar senha
    const salt = await bcrypt.genSalt(12)
    const passwordHash = await bcrypt.hash(password, salt)

    //Criar usuário
    const user = new User({
        name,
        email,
        password: passwordHash,
    })

    try {

        await user.save()

        res.status(201).json({msg: 'Usuário criado com suceso!'})

    } catch (error) {
        console.log(error)
        res.status(500).json({msg: error})
    }
})

//Login do User
app.post('/auth/login', async (req,res) => {
    //dados para o login
    const {email, password} = req.body

    //validar dados
    if (!email) {
        return res.status(422).json({msg: 'O email é obrigatório!'})
    }
    if (!password) {
        return res.status(422).json({msg: 'A senha é obrigatória!'})
    }

    //ver se esse usuário existe
    const user = await User.findOne({ email: email })

    if(!user) {
        return res.status(404).json({msg: 'Usuário não encontrado'})
    }

    // ver se a senha combina com o banco
    const checkPassword = await bcrypt.compare(password, user.password)

    if(!checkPassword) {
        return res.status(422).json({msg: 'Senha inválida'})
    }

    try{
        const secret = process.env.SECRET

        const token = jwt.sign(
            {
                id: user._id,
            },
            secret,
        )

        res.status(200).json({msg:'Autenticação realizada com sucesso!', token})

    } catch(err) {
        console.log(err)
        res.status(500).json({msg:'Aconteceu um erro no servidor, tente novamente mais tarde!'})
    }

})

//Credential
const DB_USER = process.env.DB_USER
const DB_PASSWORD = encodeURIComponent(process.env.DB_PASSWORD)

mongoose.connect(`mongodb+srv://${DB_USER}:${DB_PASSWORD}@cluster0.mxxhgnb.mongodb.net/?retryWrites=true&w=majority`)
.then( () => { //quando da certo
    console.log('Conectamos ao MongoDB!')
    app.listen(3000)
}) 
.catch((err) => {console.log(err)}) //quando der errado
