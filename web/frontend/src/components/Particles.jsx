import { useEffect, useState } from "react";

export default function Particles() {
  const [particles, setParticles] = useState([]);
  useEffect(() => {
    const p = Array.from({ length: 40 }, (_, i) => ({
      id: i,
      left: Math.random() * 100,
      delay: Math.random() * 20,
      duration: 15 + Math.random() * 20,
      size: 1 + Math.random() * 3,
      opacity: 0.2 + Math.random() * 0.6,
    }));
    setParticles(p);
  }, []);
  return (
    <div className="fixed inset-0 pointer-events-none -z-5 overflow-hidden">
      {particles.map((p) => (
        <div
          key={p.id}
          className="absolute rounded-full bg-amber-400 animate-float-up"
          style={{
            left: `${p.left}%`,
            bottom: "-10px",
            width: p.size,
            height: p.size,
            opacity: p.opacity,
            animationDelay: `${p.delay}s`,
            animationDuration: `${p.duration}s`,
            boxShadow: "0 0 6px #FFD700, 0 0 12px #DAA520",
          }}
        />
      ))}
    </div>
  );
}
