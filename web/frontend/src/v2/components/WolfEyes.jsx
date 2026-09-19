import { useEffect, useState } from "react"

/**
 * WolfEyes — Falcon MAG signature element
 *
 * Modes:
 *   - fixed=false (default): Small static eyes for sidebar/header
 *   - fixed=true: Subtle animated background eyes (low opacity, non-intrusive)
 */
export default function WolfEyes({ size = 36, fixed = false, opacity = 0.12 }) {
  if (!fixed) {
    return (
      <div
        className="flex items-center justify-center shrink-0"
        style={{ width: size, height: size }}
      >
        <div className="flex gap-1">
          <Eye width={size * 0.4} height={size * 0.22} glow={6} />
          <Eye width={size * 0.4} height={size * 0.22} glow={6} />
        </div>
      </div>
    )
  }
  return <BackgroundEyes opacity={opacity} />
}

function Eye({ width, height, glow = 6 }) {
  return (
    <div
      style={{
        width,
        height,
        borderRadius: "50%",
        background:
          "radial-gradient(circle, #ff0000 30%, #8b0000 60%, transparent 80%)",
        boxShadow: `0 0 ${glow}px #ff0000, 0 0 ${glow * 2}px #dc2626`,
      }}
    />
  )
}

function BackgroundEyes({ opacity = 0.12 }) {
  const [eyes, setEyes] = useState([])

  useEffect(() => {
    const spawnEye = () => {
      const id = Date.now() + Math.random()
      const eye = {
        id,
        top: 15 + Math.random() * 70,
        left: 5 + Math.random() * 90,
        size: 20 + Math.random() * 20,
        duration: 3000 + Math.random() * 3000,
      }
      setEyes((p) => [...p, eye])
      setTimeout(() => {
        setEyes((p) => p.filter((e) => e.id !== id))
      }, eye.duration)
    }

    const i = setInterval(spawnEye, 5000)
    spawnEye()
    return () => clearInterval(i)
  }, [])

  return (
    <div
      className="fixed inset-0 pointer-events-none overflow-hidden"
      style={{ opacity, zIndex: 0 }}
      aria-hidden="true"
    >
      {eyes.map((e) => (
        <div
          key={e.id}
          className="absolute"
          style={{
            top: `${e.top}%`,
            left: `${e.left}%`,
            animation: `eyeFade ${e.duration}ms ease-in-out`,
          }}
        >
          <div className="flex gap-2">
            <Eye width={e.size} height={e.size * 0.5} glow={10} />
            <Eye width={e.size} height={e.size * 0.5} glow={10} />
          </div>
        </div>
      ))}
      <style>{`
        @keyframes eyeFade {
          0%   { opacity: 0; transform: scale(0.8); }
          50%  { opacity: 1; transform: scale(1); }
          100% { opacity: 0; transform: scale(0.8); }
        }
      `}</style>
    </div>
  )
}