function initSessionTimer(ttlSeconds) {
    const ttl = ttlSeconds * 1000;

    setTimeout(() => {
        if (confirm("Ваша сессия истекает! Хотите продлить?")) {
            fetch("/refresh_session")
                .then(() => {
                    alert("Сессия продлена");
                    location.reload();
                });
        } else {
            window.location.href = "/logout";
        }
    }, ttl - 10000);

    setTimeout(() => {
        window.location.href = "/logout";
    }, ttl);
}
