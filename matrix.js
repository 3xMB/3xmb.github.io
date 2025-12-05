(function () {
  "use strict";

  var canvas = document.getElementById("matrixCanvas");
  if (!canvas) return;

  var ctx = canvas.getContext("2d");
  var width, height, columns, drops, fontSize;

  // ========== PUBLIC FUNCTION FOR THEME SYSTEM ==========
  window.setMatrixColor = function (color) {
    window.MATRIX_COLOR = color || "#00ff88";
  };

  // ========== INITIALIZATION ==========
  function init() {
    width = window.innerWidth;
    height = window.innerHeight;

    canvas.width = width;
    canvas.height = height;

    // heavy mode
    fontSize = 14;
    columns = Math.floor(width / fontSize);

    drops = [];
    for (var i = 0; i < columns; i++) {
      drops[i] = Math.floor(Math.random() * -40); // random above screen
    }

    ctx.font = fontSize + "px monospace";
  }

  // Matrix Characters
  var chars = "アカサタナハマヤラワ0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ#$%&+";

  // ========== DRAW FRAME ==========
  function draw() {
    // Trail effect
    ctx.fillStyle = "rgba(0, 0, 0, 0.12)";
    ctx.fillRect(0, 0, width, height);

    // matrix color from theme
    ctx.fillStyle = window.MATRIX_COLOR || "#00ff88";

    for (var i = 0; i < drops.length; i++) {
      var text = chars.charAt(Math.floor(Math.random() * chars.length));
      var x = i * fontSize;
      var y = drops[i] * fontSize;

      ctx.fillText(text, x, y);

      // restart drop
      if (y > height && Math.random() > 0.975) {
        drops[i] = Math.floor(Math.random() * -40);
      } else {
        drops[i] += 1.4; // fall speed
      }
    }

    window.requestAnimationFrame(draw);
  }

  // Resize handler
  window.addEventListener("resize", function () {
    init();
  });

  // Boot
  init();
  window.MATRIX_COLOR = "#00ff88"; // default
  draw();

})();
