import { Link } from "@/src/i18n/routing"
import { useTranslations } from "next-intl"

export default function HomePage() {
  const t = useTranslations("HomePage")

  return (
    <div>
      <h1>{t("title")}</h1>
      <Link href="/about">{t("about")}</Link>
    </div>
  )
}
