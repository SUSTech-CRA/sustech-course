(function () {
  // 获取所有 class="review-content" 的元素
  var reviewContents = document.querySelectorAll('.review-content');

  // 将所有这些元素的文本内容合并
  var combinedText = Array.from(reviewContents).map(el => el.textContent).join(' ');

  // 检查合并的文本是否包含 LaTeX 控制字符
  if (combinedText.match(/(?:\$|\\\(|\\\[|\\begin\{.*?})/)) {
    console.log('MathJax is needed');

    // 如果还没有加载 MathJax，则进行加载
    if (!window.MathJax) {
      window.MathJax = {
        tex: {inlineMath: [["$", "$"], ["\\(", "\\)"]]},
        svg: {
          fontCache: 'global'
        }
      };

      var script = document.createElement('script');
      script.src = 'https://mirrors.sustech.edu.cn/cdnjs/ajax/libs/mathjax/3.2.2/es5/tex-mml-chtml.min.js';
      document.head.appendChild(script);
    }
  }
})();
