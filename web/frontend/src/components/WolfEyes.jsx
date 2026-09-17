import { useEffect, useState } from "react";

export default function WolfEyes() {
  const [eyes, setEyes] = useState([]);

  useEffect(() => {
    const spawnEye = () => {
      const id = Date.now() + Math.random();
      const newEye = {
        id,
        top: 15 + Math.random() * 70,
        left: 5 + Math.random() * 90,
        size: 20 + Math.random() * 20,
        duration: 3000 + Math.random() * 3000,
      };
      setEyes((prev) => [...prev, newEye]);
      setTimeout(() => {
        setEyes((prev) => prev.filter((e) => e.id !== id));
      }, newEye.duration);
    };
    const interval = setInterval(spawnEye, 4000);
    spawnEye();
    return () => clearInterval(interval);
  }, []);

  return (
    <div className="fixed inset-0 pointer-events-none -z-5 overflow-hidden">
      {eyes.map((eye) => (
        <div
          key={eye.id}
          className="absolute animate-eye-blink"
          style={{ top: `${eye.top}%`, left: `${eye.left}%`, animationDuration: `${eye.duration}ms` }}
        >
          <div className="flex gap-2">
            <div
              className="rounded-full"
              style={{
                width: eye.size,
                height: eye.size * 0.5,
                background: "radial-gradient(circle, #ff0000 30%, #8b0000 60%, transparent 80%)",
                boxShadow: "0 0 20px #ff0000, 0 0 40px #dc2626",
              }}
            />
            <div
              className="rounded-full"
              style={{
                width: eye.size,
                height: eye.size * 0.5,
                background: "radial-gradient(circle, #ff0000 30%, #8b0000 60%, transparent 80%)",
                boxShadow: "0 0 20px #ff0000, 0 0 40px #dc2626",
              }}
            />
          </div>
        </div>
      ))}
    </div>
  );
}
