(function(){
    addEventListener("load", (event) => {
        let data = document.getElementById("info").dataset
        let handleState = function(state){
            if(state === "Error"){
                window.location.assign(data.redirect_url + '?state='+ data.state +'&error=' + irmaPopup.stateMachine._state);
            }
        }

        if data.server_events_enabled:
            let = serverSentEvents: {
			  endpoint: 'statusevents',
			  timeout:  data.server_events_timeout
			}
		else:
			let serverSentEvents = False

        let state = {
			serverSentEvents: serverSentEvents
			polling: {
			  endpoint:   'status',
			  interval:   data.session_polling_interval,
			  startState: 'INITIALIZED'
			}
		}
        let options = {
            // Developer options
            debugging: false,

            // Front-end options
            language:  'en',
            translations: {
                header:  data.title + ' - login',
                loading: 'Just one second please!'
            },
            state: state,

            // Back-end options
            session: {
                start: {
                    url: o => `${o.url}` + '/session/' + data.exchange_token + '/irma',
                },
                result: false,
                mapping: {
                    sessionPtr: r => r,
                },
            },
        };

        const irmaPopup = irma.newPopup({
            ...options,
            element: '#irma-web-form'
        });

        handleState(irmaPopup.stateMachine._state)
        setInterval(function () {
            handleState(irmaPopup.stateMachine._state)
        }, 1000);

        irmaPopup.start()
            .then(() => {
                window.location.assign(data.redirect_url + '?state=' + data.state);
            })
            .catch((err) => {
                window.location.assign(data.redirect_url + '?state=' + data.state + '&error=' + irmaPopup.stateMachine._state);
            });
    });
})();
