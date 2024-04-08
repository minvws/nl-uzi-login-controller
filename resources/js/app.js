import YiviPopup from '@privacybydesign/yivi-popup';
import YiviCore from '@privacybydesign/yivi-core';
import YiviClient from '@privacybydesign/yivi-client';

function init()
{
    const data = document.getElementById("info").dataset

    let serverSentEvents = false
    if (data.session_server_events_enabled.toLowerCase() === 'true') {
        serverSentEvents = {
          endpoint: 'statusevents',
          timeout:  data.session_server_events_timeout
        }
    }
    let state = {
        serverSentEvents: serverSentEvents,
        polling: {
          endpoint:   'status',
          interval:   data.session_polling_interval,
          startState: 'INITIALIZED'
        }
    }

    const yivi = new YiviCore({
        element: '#yivi-web-form',

        // Developer options
        debugging: import.meta.env.DEV,

        // Front-end options
        language:  document.documentElement.lang,
        state: state,

        // Back-end options
        session: {
            start: {
                url: o => data.base_url + '/session/' + data.exchange_token + '/yivi',
            },
            result: false,
            mapping: {
                sessionPtr: r => r,
            },
        },
    });
    yivi.use(YiviPopup);
    yivi.use(YiviClient);
    yivi.start()
        .then(() => {
            window.location.assign(data.redirect_url + '?state=' + data.state);
        })
        .catch((err) => {
            if (err === 'Aborted') {
                window.location.assign(data.redirect_url + '?state=' + data.state + '&error=login_required');
                return
            }

            let url = new URL(data.redirect_url + '?state=' + data.state + '&error=unknown_exception');
            url.searchParams.append('error_description', err);
            window.location.assign(url);
        });
}

addEventListener("load", init)
