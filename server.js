const express = require('express');
const cors = require('cors');
const dotenv = require('doteenv');
const authRoutes = require('./src/routes/auth.routes');

dotenv.config();

const app = express();
app.use(cors());
app.use(express.json());

app.use('/api/auth', authRoutes);

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));