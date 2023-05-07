const deleteProduct = (btnElement) => {
    // access the product ID and CSRF tokens
    const productId = btnElement.parentNode.querySelector('[name=productId').value;
    const csrf      = btnElement.parentNode.querySelector('[name=_csrf').value;

    // get the card HTML element of the Delete button clicked
    const cardElement = btnElement.closest(".card");
    
    // send the HTTP request (fetch is a modern replacement of XMLHttpRequest)
    fetch("/admin/product/" + productId, {
        method: "DELETE",
        headers: { "csrf-token": csrf }
    })
    .then((response) => {
        return response.json();
    })
    .then((result) => {
        console.log(result);
        if (result.success) {
            // remove the card from the DOM
            cardElement.remove();
        }
    })
    .catch((err) => {
        console.log(err);
    });
};