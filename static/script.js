// CloudGuard Dashboard
// Gets security information from the Flask API.
// Flask gets the information from the Supabase PostgreSQL database.

const LEVELS = [
    "Low",
    "Medium",
    "High",
    "Critical"
];

const COLORS = [
    "#16a34a",
    "#d97706",
    "#ea580c",
    "#dc2626"
];

let chart = null;


/* ---------------- BASIC TEXT UPDATE ---------------- */

function setText(id, value) {

    const element = document.getElementById(id);

    if (element) {
        element.textContent = value;
    }

}


/* ---------------- TABLE CELL ---------------- */

function makeCell(text) {

    const td = document.createElement("td");

    td.textContent = text;

    return td;

}


/* ---------------- SUMMARY CARDS ---------------- */

function renderCards(stats) {

    setText("total", stats.total);

    setText("failed", stats.failed_logins);

    setText("honeypot", stats.honeypot_hits);

    setText("highrisk", stats.high_risk);

}


/* ---------------- CHART ---------------- */

function renderChart(stats) {

    if (typeof Chart === "undefined") {

        return;

    }


    const values = [
        stats.low,
        stats.medium,
        stats.high,
        stats.critical
    ];


    if (chart === null) {

        chart = new Chart(
            document.getElementById("riskChart"),
            {

                type: "bar",

                data: {

                    labels: LEVELS,

                    datasets: [

                        {
                            label: "Security Events",

                            data: values,

                            backgroundColor: COLORS,

                            borderRadius: 6
                        }

                    ]

                },


                options: {

                    responsive: true,

                    maintainAspectRatio: false,

                    plugins: {

                        legend: {
                            display: false
                        }

                    },


                    scales: {

                        y: {

                            beginAtZero: true,

                            ticks: {
                                precision: 0
                            }

                        }

                    }

                }

            }
        );

    }

    else {

        chart.data.datasets[0].data = values;

        chart.update();

    }

}


/* ---------------- ALERTS ---------------- */

function renderAlerts(alerts) {

    const box =
        document.getElementById("alerts");


    box.innerHTML = "";


    alerts.forEach(function (a) {


        const div =
            document.createElement("div");


        div.className =
            "alert " +
            a.risk_level.toLowerCase();


        const title =
            document.createElement("strong");


        if (a.risk_level === "Critical") {

            title.textContent =
                "🚨 CRITICAL RISK ACTIVITY DETECTED";

        }

        else {

            title.textContent =
                "⚠️ HIGH RISK ACTIVITY DETECTED";

        }


        div.appendChild(title);


        const details = [

            ["IP Address", a.ip],

            ["Activity", a.activity],

            ["Risk Score", a.risk_score],

            ["Time", a.date + " " + a.time]

        ];


        details.forEach(function (item) {


            const p =
                document.createElement("p");


            p.textContent =
                item[0] + ": " + item[1];


            div.appendChild(p);

        });


        box.appendChild(div);

    });

}


/* ---------------- EVENTS TABLE ---------------- */

function renderEvents(events) {

    const body =
        document.getElementById("events-body");


    body.innerHTML = "";


    if (events.length === 0) {


        const tr =
            document.createElement("tr");


        const td =
            makeCell(
                "No security events yet. Use the demo buttons above."
            );


        td.colSpan = 7;


        tr.appendChild(td);


        body.appendChild(tr);


        return;

    }


    events.forEach(function (event) {


        const tr =
            document.createElement("tr");


        const values = [

            event.date,

            event.time,

            event.ip,

            event.activity,

            event.endpoint

        ];


        values.forEach(function (value) {

            tr.appendChild(
                makeCell(value)
            );

        });


        /* Risk badge */

        const riskCell =
            document.createElement("td");


        const badge =
            document.createElement("span");


        badge.className =
            "badge " +
            event.risk_level.toLowerCase();


        badge.textContent =
            event.risk_level;


        riskCell.appendChild(badge);


        tr.appendChild(riskCell);


        /* Risk score */

        tr.appendChild(
            makeCell(event.risk_score)
        );


        body.appendChild(tr);

    });

}


/* ---------------- LOAD DASHBOARD ---------------- */

async function loadDashboard() {

    try {


        const response =
            await fetch("/api/dashboard");


        if (response.status === 401) {

            window.location.href = "/";

            return;

        }


        const data =
            await response.json();


        if (!response.ok) {

            throw new Error(
                data.error ||
                "Unable to load dashboard"
            );

        }


        renderCards(data.stats);

        renderChart(data.stats);

        renderAlerts(data.alerts);

        renderEvents(data.events);


        setText(
            "status",

            "Live cloud data • Updated " +
            new Date().toLocaleTimeString()
        );


    }

    catch (error) {


        setText(
            "status",

            "Unable to load cloud data"
        );


        console.error(
            "CloudGuard error:",
            error
        );

    }

}


/* ---------------- DEMO BUTTONS ---------------- */

async function simulate(kind) {


    const buttons =
        document.querySelectorAll(".demo-btn");


    buttons.forEach(function (button) {

        button.disabled = true;

    });


    try {


        const response =
            await fetch(
                "/simulate/" + kind,
                {
                    method: "POST"
                }
            );


        if (!response.ok) {

            throw new Error(
                "Could not create demo event"
            );

        }


        await loadDashboard();

    }


    catch (error) {

        console.error(error);

    }


    finally {


        buttons.forEach(function (button) {

            button.disabled = false;

        });

    }

}


/* ---------------- START ---------------- */

if (
    document.getElementById("riskChart")
) {

    loadDashboard();


    setInterval(
        loadDashboard,
        5000
    );

}