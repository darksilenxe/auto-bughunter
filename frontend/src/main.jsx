import React from "react";
import { createRoot } from "react-dom/client";
import { BrowserRouter } from "react-router-dom";
import App from "./App";
import { ScanProvider } from "./context/ScanContext";
import "./styles.css";

createRoot(document.getElementById("root")).render(
  <React.StrictMode>
    <BrowserRouter>
      <ScanProvider>
        <App />
      </ScanProvider>
    </BrowserRouter>
  </React.StrictMode>
);
