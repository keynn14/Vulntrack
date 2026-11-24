using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace VulnTrack.Data.Migrations
{
    /// <inheritdoc />
    public partial class AddClosedCountAndNullableAssetOwner : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<int>(
                name: "ClosedCount",
                table: "ImportBatches",
                type: "int",
                nullable: false,
                defaultValue: 0);

            migrationBuilder.AlterColumn<string>(
                name: "OwnerUserId",
                table: "Assets",
                type: "nvarchar(450)",
                nullable: true,
                oldClrType: typeof(string),
                oldType: "nvarchar(450)");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "ClosedCount",
                table: "ImportBatches");

            migrationBuilder.AlterColumn<string>(
                name: "OwnerUserId",
                table: "Assets",
                type: "nvarchar(450)",
                nullable: false,
                defaultValue: "",
                oldClrType: typeof(string),
                oldType: "nvarchar(450)",
                oldNullable: true);
        }
    }
}
