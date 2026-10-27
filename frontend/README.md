# AOD-IPS Frontend

React + TypeScript frontend for **AOD-IPS**, built with Vite and Tailwind CSS.

---

## Features
- **Vite 6** + **React 18** + **TypeScript** for fast development and type safety.
- **Tailwind CSS v3** configured via PostCSS.
- **Axios client** (`src/api.ts`) configured with `VITE_API_URL` environment variable.
- Single verification page checking the backend's `/health` endpoint on load with real-time latency diagnostics.

---

## Directory Structure

```text
frontend/
├── src/
│   ├── api.ts              # Axios instance configured with VITE_API_URL
│   ├── App.tsx             # Single-page health verification component
│   ├── index.css           # Tailwind base styles and custom font configurations
│   ├── main.tsx            # React DOM root entrypoint
│   └── vite-env.d.ts       # Vite TypeScript environment declarations
├── .env.example            # Environment variables template
├── .env                    # Local environment config (VITE_API_URL=http://localhost:8000)
├── index.html              # HTML shell
├── package.json            # Scripts & dependencies
├── postcss.config.js       # PostCSS plugins (tailwindcss, autoprefixer)
├── tailwind.config.js      # Tailwind CSS configuration
├── tsconfig.json           # TypeScript configuration
├── tsconfig.node.json      # Vite Node TypeScript configuration
├── vite.config.ts          # Vite build & dev server configuration
└── README.md               # Frontend setup & execution guide
```

---

## Setup & Running

### 1. Prerequisites
- Node.js (v18+) and npm.

### 2. Navigate to frontend directory
```bash
cd frontend
```

### 3. Install Dependencies
```bash
npm install
```

### 4. Configure Environment
Ensure `.env` exists (copied from `.env.example` if needed):
```env
VITE_API_URL=http://localhost:8000
```

### 5. Start the Development Server
```bash
npm run dev
```

The frontend will run at:
- **Local:** [http://localhost:5173](http://localhost:5173)

---

## Build for Production teahh3
```bash
npm run build
```
This produces optimized production assets inside the `dist/` directory.
