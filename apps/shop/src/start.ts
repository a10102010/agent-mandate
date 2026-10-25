import { app } from "./server.js";
const PORT = parseInt(process.env.PORT ?? "3300");
app.listen(PORT, () => console.log(`[shop] on :${PORT}`));
