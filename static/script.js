document.getElementById("apiTestForm").addEventListener("submit", function(event) {
    event.preventDefault();
    const apiUrl = document.getElementById("apiUrl").value;

    fetch('/run-tests', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({ url: apiUrl })
    })
    .then(response => response.json())  // Ensures that the response is treated as JSON
    .then(data => {
        if (data.report) {
            document.getElementById("results").innerHTML = `<pre>${data.report}</pre>`;
        } else if (data.error) {
            document.getElementById("results").innerHTML = `<p>Error: ${data.error}</p>`;
        }
    })
    .catch(error => {
        document.getElementById("results").innerHTML = `Error: ${error.message}`;
    });
});
