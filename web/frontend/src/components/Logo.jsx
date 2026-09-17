export default function Logo({ size = 90 }) {
  return (
    <div className="relative inline-block" style={{ width: size, height: size }}>
      <div className="absolute inset-0 blur-3xl opacity-70 animate-pulse pointer-events-none" style={{ background: "radial-gradient(circle, #FFD700 0%, #DAA520 40%, transparent 70%)", transform: "scale(1.3)" }} />
      <img
        src="/logo.png"
        alt="Falcon MAG"
        className="relative w-full h-full object-contain animate-flicker"
        style={{
          filter: "drop-shadow(0 0 12px rgba(255, 215, 0, 0.8)) drop-shadow(0 0 25px rgba(218, 165, 32, 0.6))",
        }}
      />
    </div>
  );
}
