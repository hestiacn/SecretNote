document.addEventListener('DOMContentLoaded', function() {
    const toggleButton = document.querySelector('.password-toggle');
    const passwordInput = document.getElementById('password-input');

    if (toggleButton && passwordInput) {
        toggleButton.addEventListener('click', function() {
            // 切换密码可见性
            const isPasswordVisible = passwordInput.type === 'password';
            passwordInput.type = isPasswordVisible ? 'text' : 'password';

            // 切换图标
            const icon = toggleButton.querySelector('i');
            if (icon) {
                icon.classList.toggle('bi-eye');
                icon.classList.toggle('bi-eye-slash');

                // 切换按钮标题
                toggleButton.setAttribute('title', isPasswordVisible ? '隐藏密码' : '显示密码');
            }
        });
    }
});