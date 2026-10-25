import { app } from "./server.js";
const PORT = parseInt(process.env.PORT ?? "3100");
app.listen(PORT, () => console.log(`[approve] on :${PORT}`));
