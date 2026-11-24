// VulnTrack landing page interactions & canvas animations (vanilla ES module)

let S = null;

const STAGES = [
    {
        caption: "Greenbone reports CVE-2024-21887 on vpn-gw-01 during the nightly scan. VulnTrack imports it as a new finding.",
        priority: "Not ranked yet",
        owner: "Unassigned",
        due: "Not set",
        statusText: "Open",
        statusKey: "open"
    },
    {
        caption: "CVSS 9.1 on an internet-facing gateway that every remote employee depends on. It moves to the top of the queue.",
        priority: "P1, critical",
        owner: "Unassigned",
        due: "Not set",
        statusText: "Open",
        statusKey: "open"
    },
    {
        caption: "The network team owns the asset. Maria Santos accepts the finding with a seven-day deadline.",
        priority: "P1, critical",
        owner: "M. Santos, Network",
        due: "30 Nov 2026",
        statusText: "In progress",
        statusKey: "progress"
    },
    {
        caption: "The vendor patch is applied and the owner marks it fixed. VulnTrack keeps it open until a rescan confirms.",
        priority: "P1, critical",
        owner: "M. Santos, Network",
        due: "30 Nov 2026",
        statusText: "Fixed, awaiting verification",
        statusKey: "fixed"
    },
    {
        caption: "The follow-up Greenbone scan no longer detects the vulnerability. The finding closes with the rescan as evidence.",
        priority: "P1, critical",
        owner: "M. Santos, Network",
        due: "Closed 27 Nov 2026",
        statusText: "Closed, verified by rescan",
        statusKey: "closed"
    }
];

function clamp(v, min, max) {
    return v < min ? min : v > max ? max : v;
}

function lerp(a, b, t) {
    return a + (b - a) * t;
}

function mulberry32(seed) {
    let a = seed >>> 0;
    return function () {
        a |= 0;
        a = (a + 0x6D2B79F5) | 0;
        let t = Math.imul(a ^ (a >>> 15), 1 | a);
        t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
        return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
    };
}

function on(target, type, fn, opts) {
    if (!target || !S) return;
    target.addEventListener(type, fn, opts);
    S.listeners.push([target, type, fn, opts]);
}

function createNetwork(canvas, { count, seed, mode }) {
    if (!canvas) return null;
    const ctx = canvas.getContext("2d");
    if (!ctx) return null;

    const rand = mulberry32(seed);
    const nodes = [];
    const vulnIndices = [];

    for (let i = 0; i < count; i++) {
        const d = rand();
        const vuln = mode === "closing" ? true : rand() < 0.6;
        if (vuln) vulnIndices.push(i);

        nodes.push({
            x: (rand() * 2.5) - 1.25,
            y: (rand() * 2.1) - 1.05,
            d,
            z: 1 + d * 2.2,
            phase: rand() * Math.PI * 2,
            vuln,
            fixAt: 1,
            wasFixed: !vuln,
            ringT: -Infinity,
            sev: rand() < 0.55 ? "Critical" : "High",
            cve: `CVE-202${2 + Math.floor(rand() * 3)}-${1000 + Math.floor(rand() * 48000)}`,
            sx: 0,
            sy: 0,
            sr: 2,
            shown: false
        });
    }

    // Spread fix thresholds smoothly (shuffled) so nodes remediate one by one
    const minFix = mode === "closing" ? 0.1 : 0.12;
    const maxFix = mode === "closing" ? 0.92 : 0.9;
    const order = vulnIndices.slice();
    for (let i = order.length - 1; i > 0; i--) {
        const j = Math.floor(rand() * (i + 1));
        const tmp = order[i];
        order[i] = order[j];
        order[j] = tmp;
    }
    const denom = Math.max(1, order.length - 1);
    for (let i = 0; i < order.length; i++) {
        nodes[order[i]].fixAt = minFix + (i / denom) * (maxFix - minFix);
    }

    // Link each node to its 2 nearest neighbors in (x, y), deduplicated
    const seen = new Set();
    const links = [];
    for (let i = 0; i < count; i++) {
        const dists = [];
        for (let j = 0; j < count; j++) {
            if (i === j) continue;
            const dx = nodes[i].x - nodes[j].x;
            const dy = nodes[i].y - nodes[j].y;
            dists.push({ j, dist: dx * dx + dy * dy });
        }
        dists.sort((a, b) => a.dist - b.dist);
        for (let k = 0; k < 2 && k < dists.length; k++) {
            const j = dists[k].j;
            const a = i < j ? i : j;
            const b = i < j ? j : i;
            const key = `${a}-${b}`;
            if (!seen.has(key)) {
                seen.add(key);
                links.push([a, b, (nodes[a].d + nodes[b].d) * 0.5]);
            }
        }
    }

    return {
        canvas,
        ctx,
        nodes,
        links,
        w: 0,
        h: 0,
        visible: true
    };
}

function resizeCanvas(canvas, ctx) {
    if (!canvas || !ctx) return { w: 0, h: 0 };
    const w = canvas.clientWidth;
    const h = canvas.clientHeight;
    const dpr = Math.min(window.devicePixelRatio || 1, 2);
    const pw = Math.round(w * dpr);
    const ph = Math.round(h * dpr);
    if (canvas.width !== pw || canvas.height !== ph) {
        canvas.width = pw;
        canvas.height = ph;
    }
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    return { w, h };
}

function drawNet(net, camZ, fixProgress, t, mouse, animate) {
    if (!net || net.w <= 0 || net.h <= 0) return;

    const { ctx, nodes, links, w, h } = net;
    ctx.clearRect(0, 0, w, h);

    const cx = w * 0.5;
    const cy = h * 0.5;

    for (let i = 0; i < nodes.length; i++) {
        const n = nodes[i];
        const rel = n.z - camZ;
        if (rel < 0.06) {
            n.shown = false;
            continue;
        }

        const s = 1 / rel;
        const wobX = animate ? Math.sin(t / 2600 + n.phase) * 6 : 0;
        const wobY = animate ? Math.cos(t / 2900 + n.phase) * 6 : 0;
        const px = cx + (n.x * w * 0.55 + wobX) * s + mouse.x * 28 * s;
        const py = cy + (n.y * h * 0.55 + wobY) * s + mouse.y * 18 * s;
        const r = 1.4 + 2.4 * Math.min(s, 4);

        n.sx = px;
        n.sy = py;
        n.sr = r;

        if (px < -60 || px > w + 60 || py < -60 || py > h + 60) {
            n.shown = false;
            continue;
        }
        n.shown = true;

        const fixed = !n.vuln || fixProgress >= n.fixAt;
        if (fixed && !n.wasFixed) {
            n.ringT = t;
            n.wasFixed = true;
        } else if (!fixed && n.wasFixed) {
            n.wasFixed = false;
            n.ringT = -Infinity;
        }
        n.isFixed = fixed;
    }

    // Draw connecting links first
    ctx.lineWidth = 1;
    for (let i = 0; i < links.length; i++) {
        const [ia, ib, avgD] = links[i];
        const a = nodes[ia];
        const b = nodes[ib];
        if (!a.shown || !b.shown) continue;

        const alpha = 0.06 + 0.16 * (1 - avgD);
        ctx.strokeStyle = `rgba(159, 177, 196, ${alpha.toFixed(3)})`;
        ctx.beginPath();
        ctx.moveTo(a.sx, a.sy);
        ctx.lineTo(b.sx, b.sy);
        ctx.stroke();
    }

    // Draw nodes and status halos/rings
    for (let i = 0; i < nodes.length; i++) {
        const n = nodes[i];
        if (!n.shown) continue;

        const alpha = 0.35 + 0.65 * (1 - n.d);
        const r = n.sr;

        if (!n.isFixed) {
            const pulse = animate ? Math.sin(t / 520 + n.phase) : 0;
            const haloR = r * (2.2 + pulse);
            if (haloR > 0) {
                ctx.fillStyle = "rgba(192, 57, 43, 0.18)";
                ctx.beginPath();
                ctx.arc(n.sx, n.sy, haloR, 0, Math.PI * 2);
                ctx.fill();
            }

            ctx.fillStyle = `rgba(192, 57, 43, ${alpha.toFixed(3)})`;
            ctx.beginPath();
            ctx.arc(n.sx, n.sy, r, 0, Math.PI * 2);
            ctx.fill();
        } else {
            if (animate && t - n.ringT >= 0 && t - n.ringT < 900) {
                const k = (t - n.ringT) / 900;
                ctx.strokeStyle = `rgba(20, 150, 140, ${(1 - k).toFixed(3)})`;
                ctx.lineWidth = 1.5;
                ctx.beginPath();
                ctx.arc(n.sx, n.sy, r + k * 28, 0, Math.PI * 2);
                ctx.stroke();
            }

            ctx.fillStyle = `rgba(20, 150, 140, ${alpha.toFixed(3)})`;
            ctx.beginPath();
            ctx.arc(n.sx, n.sy, r, 0, Math.PI * 2);
            ctx.fill();
        }
    }
}

function drawRoundedRect(ctx, x, y, w, h, rad) {
    ctx.beginPath();
    ctx.moveTo(x + rad, y);
    ctx.lineTo(x + w - rad, y);
    ctx.quadraticCurveTo(x + w, y, x + w, y + rad);
    ctx.lineTo(x + w, y + h - rad);
    ctx.quadraticCurveTo(x + w, y + h, x + w - rad, y + h);
    ctx.lineTo(x + rad, y + h);
    ctx.quadraticCurveTo(x, y + h, x, y + h - rad);
    ctx.lineTo(x, y + rad);
    ctx.quadraticCurveTo(x, y, x + rad, y);
    ctx.closePath();
}

function drawLens(t, hp) {
    if (!S.lensCtx || !S.heroNet) return;
    const { lensCtx: ctx, lensW: w, lensH: h } = S;
    if (w <= 0 || h <= 0) return;

    const wantAlpha = (S.lensActive && hp < 0.5) ? 1 : 0;
    S.lensAlpha = lerp(S.lensAlpha, wantAlpha, 0.14);

    if (S.lensAlpha < 0.01) {
        S.lensInitialized = false;
        if (S.lensDrawn) {
            ctx.clearRect(0, 0, w, h);
            S.lensDrawn = false;
        }
        return;
    }

    const heroRect = S.hero.getBoundingClientRect();
    const targetX = S.lensClient.x - heroRect.left;
    const targetY = S.lensClient.y - heroRect.top;

    if (!S.lensInitialized) {
        S.lensPos.x = targetX;
        S.lensPos.y = targetY;
        S.lensInitialized = true;
    } else {
        S.lensPos.x = lerp(S.lensPos.x, targetX, 0.18);
        S.lensPos.y = lerp(S.lensPos.y, targetY, 0.18);
    }

    const lx = S.lensPos.x;
    const ly = S.lensPos.y;
    const R = 110;
    const a = S.lensAlpha;

    ctx.clearRect(0, 0, w, h);
    S.lensDrawn = true;

    // Lens outer ring and subtle tint
    ctx.fillStyle = `rgba(20, 150, 140, ${(0.05 * a).toFixed(3)})`;
    ctx.strokeStyle = `rgba(20, 150, 140, ${(0.7 * a).toFixed(3)})`;
    ctx.lineWidth = 1;
    ctx.beginPath();
    ctx.arc(lx, ly, R, 0, Math.PI * 2);
    ctx.fill();
    ctx.stroke();

    // Four cardinal tick marks
    ctx.beginPath();
    ctx.moveTo(lx, ly - R - 6);
    ctx.lineTo(lx, ly - R + 6);
    ctx.moveTo(lx, ly + R - 6);
    ctx.lineTo(lx, ly + R + 6);
    ctx.moveTo(lx - R - 6, ly);
    ctx.lineTo(lx - R + 6, ly);
    ctx.moveTo(lx + R - 6, ly);
    ctx.lineTo(lx + R + 6, ly);
    ctx.stroke();

    // Rotating radar arc + trailing strokes
    const angle = t / 900;
    ctx.strokeStyle = `rgba(20, 150, 140, ${(0.95 * a).toFixed(3)})`;
    ctx.lineWidth = 2;
    ctx.beginPath();
    ctx.arc(lx, ly, R - 2, angle, angle + 1.1);
    ctx.stroke();

    const trailAlphas = [0.45, 0.25, 0.12];
    for (let i = 0; i < trailAlphas.length; i++) {
        const end = angle - i * 0.35;
        const start = end - 0.35;
        ctx.strokeStyle = `rgba(20, 150, 140, ${(trailAlphas[i] * a).toFixed(3)})`;
        ctx.beginPath();
        ctx.arc(lx, ly, R - 2, start, end);
        ctx.stroke();
    }

    // Highlight nodes inside the lens radius
    ctx.font = '500 11px "Public Sans", system-ui, sans-serif';
    ctx.textBaseline = "middle";

    const nodes = S.heroNet.nodes;
    for (let i = 0; i < nodes.length; i++) {
        const n = nodes[i];
        if (!n.shown) continue;

        const dx = n.sx - lx;
        const dy = n.sy - ly;
        if (dx * dx + dy * dy > R * R) continue;

        const ringColor = n.isFixed
            ? `rgba(46, 139, 87, ${(0.95 * a).toFixed(3)})`
            : `rgba(192, 57, 43, ${(0.95 * a).toFixed(3)})`;
        ctx.strokeStyle = ringColor;
        ctx.lineWidth = 1;
        ctx.beginPath();
        ctx.arc(n.sx, n.sy, n.sr + 5, 0, Math.PI * 2);
        ctx.stroke();

        const statusLabel = n.isFixed ? "Verified" : n.sev;
        const cveText = n.cve;
        const sep = " · ";
        const cveW = ctx.measureText(cveText + sep).width;
        const statusW = ctx.measureText(statusLabel).width;
        const padX = 7;
        const boxW = cveW + statusW + padX * 2;
        const boxH = 20;

        let bx = n.sx + n.sr + 10;
        if (bx + boxW > w - 8) {
            bx = n.sx - n.sr - 10 - boxW;
        }
        const by = clamp(n.sy - boxH * 0.5, 8, h - boxH - 8);

        ctx.fillStyle = `rgba(11, 24, 41, ${(0.86 * a).toFixed(3)})`;
        drawRoundedRect(ctx, bx, by, boxW, boxH, 4);
        ctx.fill();

        ctx.strokeStyle = `rgba(255, 255, 255, ${(0.12 * a).toFixed(3)})`;
        ctx.lineWidth = 1;
        ctx.stroke();

        const ty = by + boxH * 0.5 + 0.5;
        ctx.fillStyle = `rgba(232, 238, 244, ${(0.95 * a).toFixed(3)})`;
        ctx.fillText(cveText + sep, bx + padX, ty);

        ctx.fillStyle = n.isFixed
            ? `rgba(76, 195, 128, ${(0.98 * a).toFixed(3)})`
            : `rgba(230, 103, 90, ${(0.98 * a).toFixed(3)})`;
        ctx.fillText(statusLabel, bx + padX + cveW, ty);
    }
}

function updateStory(scrollY, reduced, interactiveTilt) {
    if (!S.story || !S.storyStage) return;

    const sectionRect = S.story.getBoundingClientRect();
    const sectionTop = sectionRect.top + scrollY;
    const travel = Math.max(1, S.story.offsetHeight - window.innerHeight);
    const p = clamp((scrollY - sectionTop) / travel, 0, 1);
    const stage = Math.min(4, Math.floor(p * 5));

    if (S.storyBar) {
        S.storyBar.style.width = `${(p * 100).toFixed(2)}%`;
    }

    if (stage !== S.lastStage) {
        const prevStage = S.lastStage;
        S.lastStage = stage;
        S.storyStage.dataset.stage = String(stage);

        for (let i = 0; i < S.storySteps.length; i++) {
            const li = S.storySteps[i];
            li.classList.toggle("is-done", i <= stage);
            li.classList.toggle("is-current", i === stage);
        }

        const data = STAGES[stage];
        const setField = (el, text) => {
            if (!el || el.textContent === text) return;
            el.textContent = text;
            if (prevStage !== -1 && !reduced) {
                el.classList.remove("is-changed");
                void el.offsetWidth;
                el.classList.add("is-changed");
            }
        };

        setField(S.fields.caption, data.caption);
        setField(S.fields.priority, data.priority);
        setField(S.fields.owner, data.owner);
        setField(S.fields.due, data.due);

        if (S.fields.status) {
            setField(S.fields.status, data.statusText);
            S.fields.status.dataset.status = data.statusKey;
        }
    }

    if (S.storyTilt) {
        const inView = sectionRect.bottom > 0 && sectionRect.top < window.innerHeight;
        if (interactiveTilt && inView) {
            const rx = (S.mouse.y * -5).toFixed(2);
            const ry = (S.mouse.x * 7).toFixed(2);
            S.storyTilt.style.transform = `rotateX(${rx}deg) rotateY(${ry}deg)`;
        } else {
            S.storyTilt.style.transform = "";
        }
    }
}

function updateFeatures(reduced) {
    if (reduced || !S.featuresList || !S.featureItems.length) return;

    const listRect = S.featuresList.getBoundingClientRect();
    const vh = window.innerHeight;
    if (listRect.bottom < -100 || listRect.top > vh + 100) return;

    for (let i = 0; i < S.featureItems.length; i++) {
        const item = S.featureItems[i];
        const rect = item.getBoundingClientRect();
        const q = clamp((vh * 0.92 - rect.top) / (vh * 0.45), 0, 1);
        item.style.setProperty("--q", q.toFixed(3));
    }
}

function updateWho(reduced, narrow) {
    if (!S.who || !S.whoCols.length) return;
    if (reduced || narrow) {
        for (let i = 0; i < S.whoCols.length; i++) {
            S.whoCols[i].style.transform = "";
        }
        return;
    }

    const rect = S.who.getBoundingClientRect();
    const vh = window.innerHeight;
    if (rect.bottom < 0 || rect.top > vh) return;

    const p = clamp((vh - rect.top) / (vh + rect.height), 0, 1);
    for (let i = 0; i < S.whoCols.length; i++) {
        const col = S.whoCols[i];
        const speed = Number(col.dataset.speed) || 0;
        const ty = (0.5 - p) * speed;
        col.style.transform = `translate3d(0, ${ty.toFixed(2)}px, 0)`;
    }
}

function handleResize() {
    if (S.heroNet) {
        const sz = resizeCanvas(S.heroNet.canvas, S.heroNet.ctx);
        S.heroNet.w = sz.w;
        S.heroNet.h = sz.h;
    }
    if (S.closingNet) {
        const sz = resizeCanvas(S.closingNet.canvas, S.closingNet.ctx);
        S.closingNet.w = sz.w;
        S.closingNet.h = sz.h;
    }
    if (S.lensCanvas && S.lensCtx) {
        const sz = resizeCanvas(S.lensCanvas, S.lensCtx);
        S.lensW = sz.w;
        S.lensH = sz.h;
    }

    if (S.reduced) {
        const zeroMouse = { x: 0, y: 0 };
        drawNet(S.heroNet, 0, 0, 0, zeroMouse, false);
        drawNet(S.closingNet, 0, 1, 0, zeroMouse, false);
    }
}

function tick(t) {
    if (!S) return;

    if (S.resized) {
        S.resized = false;
        handleResize();
    }

    const scrollY = window.scrollY;
    const reduced = S.reduced;
    const narrow = S.narrow;
    const coarse = S.coarse;

    if (S.nav) {
        S.nav.classList.toggle("is-solid", scrollY > 40);
    }

    if (!reduced) {
        S.mouse.x = lerp(S.mouse.x, S.mouseTarget.x, 0.08);
        S.mouse.y = lerp(S.mouse.y, S.mouseTarget.y, 0.08);

        if (S.hero) {
            const heroH = Math.max(1, S.hero.offsetHeight);
            const hp = clamp(scrollY / heroH, 0, 1);

            if (S.heroNet && S.heroNet.visible) {
                const camZ = hp * 0.92;
                const fixProgress = hp * 1.15;
                drawNet(S.heroNet, camZ, fixProgress, t, S.mouse, true);
            }

            if (!coarse && !narrow) {
                drawLens(t, hp);
            }

            const heroVisible = scrollY < heroH + 60;
            for (let i = 0; i < S.heroLayers.length; i++) {
                const layer = S.heroLayers[i];
                if (heroVisible) {
                    const speed = Number(layer.dataset.speed) || 0;
                    const ty = scrollY * speed;
                    const op = clamp(1 - hp * 1.2, 0, 1);
                    layer.style.transform = `translate3d(0, ${ty.toFixed(2)}px, 0)`;
                    layer.style.opacity = op.toFixed(3);
                } else {
                    layer.style.opacity = "0";
                }
            }

            for (let i = 0; i < S.heroCards.length; i++) {
                const card = S.heroCards[i];
                if (narrow) {
                    card.style.transform = "";
                } else if (heroVisible) {
                    const depth = Number(card.dataset.depth) || 0.5;
                    const tx = S.mouse.x * -22 * depth;
                    const ty = S.mouse.y * -16 * depth + scrollY * -0.08 * depth;
                    card.style.transform = `translate3d(${tx.toFixed(2)}px, ${ty.toFixed(2)}px, 0)`;
                }
            }
        }

        if (S.closing && S.closingNet && S.closingNet.visible) {
            const rect = S.closing.getBoundingClientRect();
            const vh = Math.max(1, window.innerHeight);
            const c = clamp((vh - rect.top) / (vh * 0.9), 0, 1);
            const camZ = 0.85 * (1 - c);
            const fixProgress = c * 1.08;
            const halfMouse = { x: S.mouse.x * 0.5, y: S.mouse.y * 0.5 };
            drawNet(S.closingNet, camZ, fixProgress, t, halfMouse, true);
        }

        updateFeatures(false);
        updateWho(false, narrow);
    }

    updateStory(scrollY, reduced, !reduced && !coarse && !narrow);

    S.raf = requestAnimationFrame(tick);
}

export function initHome() {
    if (S) disposeHome();

    const root = document.querySelector(".vt");
    if (!root) return;

    const mqReduced = window.matchMedia("(prefers-reduced-motion: reduce)");
    const mqCoarse = window.matchMedia("(hover: none), (pointer: coarse)");
    const mqNarrow = window.matchMedia("(max-width: 899px)");

    document.documentElement.classList.add("vt-js", "vt-intro-play");

    const hero = root.querySelector(".vt-hero");
    const closing = root.querySelector(".vt-closing");
    const heroNetCanvas = root.querySelector(".vt-hero__net");
    const closingNetCanvas = root.querySelector(".vt-closing__net");
    const lensCanvas = root.querySelector(".vt-hero__lens");
    const story = root.querySelector(".vt-story");
    const storyStage = root.querySelector(".vt-story__stage");

    S = {
        root,
        nav: root.querySelector("#vt-nav"),
        hero,
        heroNet: createNetwork(heroNetCanvas, { count: 46, seed: 202601, mode: "hero" }),
        heroLayers: Array.from(root.querySelectorAll(".vt-hero__layer")),
        heroCards: Array.from(root.querySelectorAll(".vt-fcard")),
        lensCanvas,
        lensCtx: lensCanvas ? lensCanvas.getContext("2d") : null,
        lensW: 0,
        lensH: 0,
        lensActive: false,
        lensInitialized: false,
        lensDrawn: false,
        lensAlpha: 0,
        lensClient: { x: 0, y: 0 },
        lensPos: { x: 0, y: 0 },

        story,
        storyStage,
        storyTilt: root.querySelector(".vt-story__tilt"),
        storyBar: root.querySelector(".vt-story__bar span"),
        storySteps: Array.from(root.querySelectorAll(".vt-story__steps li")),
        lastStage: -1,
        fields: {
            caption: root.querySelector('[data-field="caption"]'),
            priority: root.querySelector('[data-field="priority"]'),
            owner: root.querySelector('[data-field="owner"]'),
            due: root.querySelector('[data-field="due"]'),
            status: root.querySelector('[data-field="status"]')
        },

        featuresList: root.querySelector(".vt-features__list"),
        featureItems: Array.from(root.querySelectorAll(".vt-feature")),
        who: root.querySelector(".vt-who"),
        whoCols: Array.from(root.querySelectorAll(".vt-who__col")),
        closing,
        closingNet: createNetwork(closingNetCanvas, { count: 46, seed: 202602, mode: "closing" }),

        mouse: { x: 0, y: 0 },
        mouseTarget: { x: 0, y: 0 },
        reduced: mqReduced.matches,
        coarse: mqCoarse.matches,
        narrow: mqNarrow.matches,
        resized: false,
        raf: 0,
        listeners: [],
        observers: []
    };

    const reinit = () => {
        disposeHome();
        initHome();
    };

    on(mqReduced, "change", reinit);
    on(mqNarrow, "change", reinit);

    on(window, "scroll", () => {
        // Scroll values are sampled once per animation frame inside tick().
    }, { passive: true });

    on(window, "resize", () => {
        if (S) S.resized = true;
    }, { passive: true });

    if (!S.reduced) {
        on(window, "pointermove", (e) => {
            if (!S) return;
            const w = window.innerWidth || 1;
            const h = window.innerHeight || 1;
            S.mouseTarget.x = clamp((e.clientX / w) * 2 - 1, -1, 1);
            S.mouseTarget.y = clamp((e.clientY / h) * 2 - 1, -1, 1);
        }, { passive: true });

        if (hero && !S.coarse && !S.narrow) {
            on(hero, "pointermove", (e) => {
                if (!S || e.pointerType !== "mouse") return;
                S.lensActive = true;
                S.lensClient.x = e.clientX;
                S.lensClient.y = e.clientY;
            }, { passive: true });

            on(hero, "pointerleave", () => {
                if (!S) return;
                S.lensActive = false;
            });
        }
    }

    if ("IntersectionObserver" in window) {
        const io = new IntersectionObserver((entries) => {
            if (!S) return;
            for (let i = 0; i < entries.length; i++) {
                const entry = entries[i];
                if (entry.target === S.hero && S.heroNet) {
                    S.heroNet.visible = entry.isIntersecting;
                } else if (entry.target === S.closing && S.closingNet) {
                    S.closingNet.visible = entry.isIntersecting;
                }
            }
        }, { rootMargin: "100px 0px" });

        if (S.hero) io.observe(S.hero);
        if (S.closing) io.observe(S.closing);
        S.observers.push(io);
    }

    handleResize();

    if (S.reduced) {
        for (let i = 0; i < S.featureItems.length; i++) {
            S.featureItems[i].style.setProperty("--q", "1");
        }
        updateWho(true, S.narrow);
    }

    S.raf = requestAnimationFrame(tick);
}

export function disposeHome() {
    if (!S) return;

    if (S.raf) {
        cancelAnimationFrame(S.raf);
    }

    for (let i = 0; i < S.listeners.length; i++) {
        const [target, type, fn, opts] = S.listeners[i];
        target.removeEventListener(type, fn, opts);
    }

    for (let i = 0; i < S.observers.length; i++) {
        S.observers[i].disconnect();
    }

    document.documentElement.classList.remove("vt-js", "vt-intro-play");
    S = null;
}
