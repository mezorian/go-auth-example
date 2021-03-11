/* --- EVENT LISTENERS ---  */

$("body").on("click", "#SubmitButton", function() {
  updateData("/SignUp",
    [],
    "guest_details_name_form"
  );
});

/**
 * updateData - Run a HTTP POST request against the given APIEndpoint url.
 *              If idOfForm is provided then all data stored in this HTML is
 *              added to the data which is sent with the POST request.
 *
 *              After the HTTP request is executed the response is printed to
 *              the console and all functions which were specified in
 *              arrayOfRefreshFunctions are executed. This gives the opportunity
 *              to run functions which reload certain areas of the website after
 *              the POST request changed data on the server side.
 *
 * @param {string}     APIEndpoint             URL string to API Endpoint "/<URL>"
 *                                             example: "/getData"
 * @param {[function]} arrayOfRefreshFunctions array of function-NAMES to be executed
 *                                             after the HTTP request. Please don't
 *                                             specify any brackets or parameters here,
 *                                             as this will execute the function
 *                                             already on parameter level!
 *                                             example: [function1, function2]
 * @param {string}     [idOfForm=]             HTML id of form which holds the
 *                                             form data. Default value is "".
 *                                             In this case no form is used.
 *                                             This param. works with only the
 *                                             id, without an leading #
 *                                             example: "div_name"
 * @param {object} [dictOfValues={}]           Dictionary {string : string} which
 *                                             can hold additional form data.
 *                                             Default value is an empty dict {} .
 *                                             In this case no additional form
 *                                             is provided.
 *                                             example: {"name1": "value1",
 *                                                        "name2": "value2"}
 *
 * @return {type} Description
 */


/**
 * updateData - Description
 *
 * @param {type}   APIEndpoint             Description
 * @param {type}   arrayOfRefreshFunctions Description
 * @param {string} [idOfForm=]             Description
 * @param {object} [dictOfValues={}]       Description
 *
 * @return {type} Description
 */
function updateData(APIEndpoint, arrayOfRefreshFunctions,
  idOfForm = "", dictOfValues = {}) {
  // Create FormData object to forward this as data during
  // HTTP POST request.
  if (idOfForm != "") {
    form = document.getElementById(idOfForm);
    formData = new FormData(form);
  } else {
    formData = new FormData();
  }

  // execute HTTP POST request and print response to console
  fetch(APIEndpoint, {
      method: "post",
      body: formData,
    })
    .then(response => response.text())
    .then((response) => {
      console.log(response)
    })
    .catch(err => console.log(err))

};
