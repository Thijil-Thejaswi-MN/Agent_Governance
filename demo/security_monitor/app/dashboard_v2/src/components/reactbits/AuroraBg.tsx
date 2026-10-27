// Inspired by React Bits (https://reactbits.dev) Aurora background - MIT + Commons Clause License
import React, { useEffect, useRef } from 'react';

interface AuroraProps {
  className?: string;
  speed?: number;
}

export const AuroraBg: React.FC<AuroraProps> = ({
  className = '',
  speed = 0.8,
}) => {
  const canvasRef = useRef<HTMLCanvasElement>(null);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;

    // Check prefers-reduced-motion
    if (window.matchMedia('(prefers-reduced-motion: reduce)').matches) {
      return;
    }

    const gl = canvas.getContext('webgl');
    if (!gl) return;

    // Vertex shader
    const vsSource = `
      attribute vec2 position;
      void main() {
        gl_Position = vec4(position, 0.0, 1.0);
      }
    `;

    // Fragment shader for smooth aurora wave
    const fsSource = `
      precision mediump float;
      uniform vec2 resolution;
      uniform float time;
      
      void main() {
        vec2 uv = gl_FragCoord.xy / resolution.xy;
        float t = time * 0.4;
        
        float wave1 = sin(uv.x * 3.5 + t) * 0.25 + 0.5;
        float wave2 = cos(uv.x * 2.2 - t * 0.7) * 0.2 + 0.4;
        
        float dist1 = abs(uv.y - wave1);
        float dist2 = abs(uv.y - wave2);
        
        vec3 col1 = vec3(0.02, 0.71, 0.83); // Cyan
        vec3 col2 = vec3(0.54, 0.36, 0.96); // Violet
        
        float glow1 = 0.04 / (dist1 + 0.08);
        float glow2 = 0.04 / (dist2 + 0.08);
        
        vec3 color = col1 * glow1 + col2 * glow2;
        gl_FragColor = vec4(color * 0.4, 0.25);
      }
    `;

    const createShader = (glCtx: WebGLRenderingContext, type: number, source: string) => {
      const shader = glCtx.createShader(type);
      if (!shader) return null;
      glCtx.shaderSource(shader, source);
      glCtx.compileShader(shader);
      return shader;
    };

    const vs = createShader(gl, gl.VERTEX_SHADER, vsSource);
    const fs = createShader(gl, gl.FRAGMENT_SHADER, fsSource);
    if (!vs || !fs) return;

    const program = gl.createProgram();
    if (!program) return;
    gl.attachShader(program, vs);
    gl.attachShader(program, fs);
    gl.linkProgram(program);
    gl.useProgram(program);

    const positionBuffer = gl.createBuffer();
    gl.bindBuffer(gl.ARRAY_BUFFER, positionBuffer);
    gl.bufferData(
      gl.ARRAY_BUFFER,
      new Float32Array([-1, -1, 1, -1, -1, 1, -1, 1, 1, -1, 1, 1]),
      gl.STATIC_DRAW
    );

    const positionLocation = gl.getAttribLocation(program, 'position');
    gl.enableVertexAttribArray(positionLocation);
    gl.vertexAttribPointer(positionLocation, 2, gl.FLOAT, false, 0, 0);

    const resolutionLocation = gl.getUniformLocation(program, 'resolution');
    const timeLocation = gl.getUniformLocation(program, 'time');

    let animationFrameId: number;
    let startTime = performance.now();
    let isPaused = false;

    const resize = () => {
      if (!canvas) return;
      const dpr = Math.min(window.devicePixelRatio || 1, 1.5);
      canvas.width = canvas.clientWidth * dpr;
      canvas.height = canvas.clientHeight * dpr;
      gl.viewport(0, 0, canvas.width, canvas.height);
      gl.uniform2f(resolutionLocation, canvas.width, canvas.height);
    };

    resize();
    window.addEventListener('resize', resize);

    // Pause WebGL when tab is hidden to conserve GPU/battery
    const handleVisibilityChange = () => {
      isPaused = document.hidden;
      if (!isPaused) {
        startTime = performance.now();
        render();
      }
    };
    document.addEventListener('visibilitychange', handleVisibilityChange);

    const render = () => {
      if (isPaused) return;
      const now = performance.now();
      const elapsed = (now - startTime) * 0.001 * speed;
      gl.uniform1f(timeLocation, elapsed);
      gl.drawArrays(gl.TRIANGLES, 0, 6);
      animationFrameId = requestAnimationFrame(render);
    };

    render();

    return () => {
      cancelAnimationFrame(animationFrameId);
      window.removeEventListener('resize', resize);
      document.removeEventListener('visibilitychange', handleVisibilityChange);
      gl.deleteProgram(program);
    };
  }, [speed]);

  return (
    <canvas
      ref={canvasRef}
      className={`absolute inset-0 pointer-events-none w-full h-full opacity-60 dark:opacity-80 ${className}`}
    />
  );
};

export default AuroraBg;
