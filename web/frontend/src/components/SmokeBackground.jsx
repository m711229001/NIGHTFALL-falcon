import { useEffect, useRef } from "react";

export default function SmokeBackground() {
  const canvasRef = useRef(null);
  useEffect(() => {
    const canvas = canvasRef.current;
    const ctx = canvas.getContext("2d");
    canvas.width = window.innerWidth;
    canvas.height = window.innerHeight;
    class SmokeParticle {
      constructor() {
        this.reset();
      }
      reset() {
        this.x = Math.random() * canvas.width;
        this.y = canvas.height + Math.random() * 100;
        this.size = Math.random() * 120 + 40;
        this.opacity = Math.random() * 0.15 + 0.05;
        this.speedY = Math.random() * 0.4 + 0.15;
        this.speedX = (Math.random() - 0.5) * 0.4;
        this.hue = Math.random() > 0.5 ? "gold" : "red";
      }
      update() {
        this.y -= this.speedY;
        this.x += this.speedX;
        if (this.y < -this.size) this.reset();
      }
      draw() {
        const gradient = ctx.createRadialGradient(this.x, this.y, this.size * 0.2, this.x, this.y, this.size);
        if (this.hue === "gold") {
          gradient.addColorStop(0, `rgba(218,165,32,${this.opacity})`);
          gradient.addColorStop(0.5, `rgba(139,105,20,${this.opacity * 0.5})`);
        } else {
          gradient.addColorStop(0, `rgba(139,0,0,${this.opacity})`);
          gradient.addColorStop(0.5, `rgba(60,0,0,${this.opacity * 0.5})`);
        }
        gradient.addColorStop(1, "rgba(0,0,0,0)");
        ctx.fillStyle = gradient;
        ctx.beginPath();
        ctx.arc(this.x, this.y, this.size, 0, Math.PI * 2);
        ctx.fill();
      }
    }
    const particles = [];
    for (let i = 0; i < 60; i++) particles.push(new SmokeParticle());
    let raf;
    const animate = () => {
      ctx.clearRect(0, 0, canvas.width, canvas.height);
      particles.forEach((p) => { p.update(); p.draw(); });
      raf = requestAnimationFrame(animate);
    };
    animate();
    const onResize = () => { canvas.width = window.innerWidth; canvas.height = window.innerHeight; };
    window.addEventListener("resize", onResize);
    return () => { cancelAnimationFrame(raf); window.removeEventListener("resize", onResize); };
  }, []);
  return (
    <>
      <div className="fixed inset-0 -z-20" style={{ background: "radial-gradient(circle at center, #0a0014 0%, #000 100%)" }} />
      <canvas ref={canvasRef} className="fixed inset-0 -z-10 pointer-events-none" />
      <div className="fixed inset-0 -z-5 pointer-events-none" style={{ boxShadow: "inset 0 0 300px 100px rgba(0,0,0,0.95)" }} />
      <div className="fixed inset-0 -z-5 pointer-events-none opacity-[0.04]" style={{ backgroundImage: "repeating-linear-gradient(0deg, #FFD700 0px, #FFD700 1px, transparent 1px, transparent 4px)" }} />
    </>
  );
}
